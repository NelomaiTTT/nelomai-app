//! Single protected credential owner. The launcher must hold the cross-process
//! single-instance lock and finish migration before construction. Never retain
//! a writable RuntimeStorageSession compatibility projection beside this owner.
use async_trait::async_trait;
use nelomai_client_api::{
    AccessSnapshot, ClientApi, ClientApiError, LoginRequest, RuntimeLogoutRequest,
    RuntimeResumeRequest, RuntimeSupersedeRequest, RuntimeSupersedeResponse,
    RuntimeSwitchReconcileRequest, RuntimeSwitchReconcileResponse, RuntimeSwitchState,
    RuntimeTarget, TokenResponse,
};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, BrokerRequestKind, BrokerRequestV1,
    CompletedResumeV1, CompletedRuntimeLogoutV1, LogoutState, PendingLogoutV1,
    PendingRuntimeSupersedeV1, RuntimeLogoutSourceV1, StorageError, StoredResumeArgumentsV1,
    TransitionAuthorityV1, TransitionReconcileReceiptV1, TransitionResumeEvidenceV1,
    MAX_TRANSITION_AUTHORITIES,
};
use nelomai_client_storage::{RecoveryTicketV1, TransitionDispatchStateV1};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Only a trusted container/native adapter receives this request, never runtime IPC.
pub struct NativeAuthRequest {
    pub ticket: RecoveryTicketV1,
    pub access: AccessSnapshot,
    pub install_secret: String,
    pub expires_at_unix_ms: u64,
}
impl std::fmt::Debug for NativeAuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAuthRequest")
            .field("ticket", &self.ticket)
            .field("credentials", &"<redacted>")
            .finish()
    }
}
impl NativeAuthRequest {
    pub fn operation_json(&self) -> Result<String, BrokerError> {
        serde_json::to_string(&serde_json::json!({"ticket": self.ticket, "expires_at_unix_ms": self.expires_at_unix_ms}))
            .map_err(|_| BrokerError::RecoveryRequired)
    }
}
#[derive(Debug)]
pub enum NativeAuthFailure {
    /// Exact native/server rejection before auth issuance; no native state is erased.
    NotIssued,
    AccessUnavailable,
    OutcomeUnknown,
}

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
    #[error("application access unavailable")]
    AccessUnavailable,
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

/// Nonsecret live provenance. This is not launcher or executable authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeStamp {
    epoch: u64,
    family: String,
    identity: Option<nelomai_contracts::RuntimeIdentity>,
}
impl ScopeStamp {
    pub(crate) fn session_generation(&self) -> Option<u64> {
        self.identity
            .as_ref()
            .and_then(|identity| identity.session_generation)
    }
    pub(crate) fn runtime_scope(
        &self,
    ) -> Result<nelomai_client_storage::RuntimeAuthScope, BrokerError> {
        let scope = nelomai_client_storage::RuntimeAuthScope {
            auth_epoch: self.epoch,
            family: self.family.clone(),
            identity: self.identity.clone().ok_or(BrokerError::RecoveryRequired)?,
        };
        scope.validate()?;
        Ok(scope)
    }
    pub(crate) fn from_access(access: &AccessSnapshot) -> Self {
        Self {
            epoch: access.auth_epoch(),
            family: access.family().into(),
            identity: Some(access.identity().clone()),
        }
    }
    fn of(auth: &AuthStoreV1) -> Result<Self, BrokerError> {
        Ok(Self {
            epoch: auth.auth_epoch,
            family: auth
                .broker
                .as_ref()
                .ok_or(BrokerError::RecoveryRequired)?
                .family
                .clone(),
            identity: auth.confirmed_identity.clone(),
        })
    }
    fn check(&self, auth: &AuthStoreV1) -> Result<(), BrokerError> {
        if *self == Self::of(auth)? {
            Ok(())
        } else {
            Err(BrokerError::Cancelled)
        }
    }
}

/// Owner-captured provenance, never reconstructed from runtime request fields.
pub(crate) struct LoginFence {
    epoch: u64,
    family: String,
}

#[async_trait]
pub trait LocalAuthStop: Send + Sync {
    /// Synchronous cancellation boundary after durable epoch persistence.
    /// Remote adapters enqueue ordered revoke or close the peer on saturation;
    /// they must not await I/O or suppress subsequent physical/remote cleanup.
    fn revoke_runtime(&self) {}
    async fn stop_local(&self) -> Result<(), BrokerError>;
    /// Owner-only native cleanup handoff, after durable cancellation and before
    /// revocation HTTP. Must be genuinely asynchronous and preserve late fences.
    async fn prepare_revocation(&self, _cancel_epoch: u64) -> Result<(), BrokerError> {
        Ok(())
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSourceSnapshot {
    auth_epoch: u64,
    family: String,
    identity: Option<nelomai_contracts::RuntimeIdentity>,
    device_id: String,
    expected_session_generation: Option<u64>,
    scope_fingerprint: String,
}
impl TransitionSourceSnapshot {
    pub fn auth_epoch(&self) -> u64 {
        self.auth_epoch
    }
    pub fn family(&self) -> &str {
        &self.family
    }
    pub fn identity(&self) -> Option<&nelomai_contracts::RuntimeIdentity> {
        self.identity.as_ref()
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    pub fn expected_session_generation(&self) -> Option<u64> {
        self.expected_session_generation
    }
    pub fn scope_fingerprint(&self) -> &str {
        &self.scope_fingerprint
    }
    pub fn matches_runtime_scope(
        &self,
        scope: Option<&nelomai_client_storage::RuntimeAuthScope>,
    ) -> bool {
        match (&self.identity, scope) {
            (None, None) => true,
            (Some(identity), Some(scope)) => {
                scope.auth_epoch == self.auth_epoch
                    && scope.family == self.family
                    && &scope.identity == identity
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenReconcileRequest {
    request: RuntimeSwitchReconcileRequest,
    request_fingerprint: String,
    source_device_id: String,
    source_scope_fingerprint: String,
}
impl FrozenReconcileRequest {
    pub fn new(
        request: RuntimeSwitchReconcileRequest,
        source: &TransitionSourceSnapshot,
    ) -> Result<Self, BrokerError> {
        Self::from_persisted(
            request,
            source.device_id.clone(),
            source.scope_fingerprint.clone(),
            None,
        )
    }

    pub fn from_persisted(
        request: RuntimeSwitchReconcileRequest,
        source_device_id: String,
        source_scope_fingerprint: String,
        expected_request_fingerprint: Option<&str>,
    ) -> Result<Self, BrokerError> {
        let request_fingerprint = digest_json(&request)?;
        if expected_request_fingerprint.is_some_and(|expected| expected != request_fingerprint)
            || source_device_id.is_empty()
            || !valid_sha256(&source_scope_fingerprint)
        {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(Self {
            request,
            request_fingerprint,
            source_device_id,
            source_scope_fingerprint,
        })
    }

    pub fn request(&self) -> &RuntimeSwitchReconcileRequest {
        &self.request
    }
    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }
    pub fn source_device_id(&self) -> &str {
        &self.source_device_id
    }
    pub fn source_scope_fingerprint(&self) -> &str {
        &self.source_scope_fingerprint
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn digest_json(value: &impl serde::Serialize) -> Result<String, BrokerError> {
    fn canonical(value: &serde_json::Value, output: &mut Vec<u8>) {
        match value {
            serde_json::Value::Object(fields) => {
                output.push(b'{');
                let mut fields: Vec<_> = fields.iter().collect();
                fields.sort_unstable_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in fields.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    output.extend(serde_json::to_vec(key).expect("JSON object key"));
                    output.push(b':');
                    canonical(value, output);
                }
                output.push(b'}');
            }
            serde_json::Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    canonical(value, output);
                }
                output.push(b']');
            }
            value => output.extend(serde_json::to_vec(value).expect("JSON scalar")),
        }
    }
    let value = serde_json::to_value(value).map_err(|_| BrokerError::RecoveryRequired)?;
    let mut bytes = Vec::new();
    canonical(&value, &mut bytes);
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Debug)]
pub struct TransitionResumeReceipt {
    identity: nelomai_contracts::RuntimeIdentity,
    current_access: Option<AccessSnapshot>,
}
impl TransitionResumeReceipt {
    pub fn identity(&self) -> &nelomai_contracts::RuntimeIdentity {
        &self.identity
    }
    pub fn current_access(&self) -> Option<&AccessSnapshot> {
        self.current_access.as_ref()
    }
}

pub struct AuthBroker {
    api: ClientApi,
    store: Arc<dyn AuthStore>,
    stop: Arc<dyn LocalAuthStop>,
    state: Mutex<()>,
    issuance: Mutex<()>,
}
#[cfg(test)]
pub(crate) async fn hold_test_issuance(broker: &AuthBroker) -> tokio::sync::MutexGuard<'_, ()> {
    broker.issuance.lock().await
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
                pending_push_cleanup_epoch: None,
                transition_authorities: Vec::new(),
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

    fn save_transition_write(&self, auth: &AuthStoreV1) -> Result<(), BrokerError> {
        auth.validate_transition_write_budget()?;
        self.store.save(auth)?;
        Ok(())
    }

    fn transition_source_from_auth(
        auth: &AuthStoreV1,
    ) -> Result<TransitionSourceSnapshot, BrokerError> {
        Self::active(auth)?;
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        let device_id = meta
            .confirmed_device_id
            .clone()
            .ok_or(BrokerError::RecoveryRequired)?;
        if device_id.is_empty()
            || auth
                .confirmed_identity
                .as_ref()
                .is_some_and(|identity| identity.session_generation != auth.session_generation)
            || auth.confirmed_identity.is_none() != auth.session_generation.is_none()
        {
            return Err(BrokerError::RecoveryRequired);
        }
        let scope = serde_json::json!({
            "auth_epoch": auth.auth_epoch,
            "family": meta.family,
            "identity": auth.confirmed_identity,
            "device_id": device_id,
        });
        Ok(TransitionSourceSnapshot {
            auth_epoch: auth.auth_epoch,
            family: meta.family.clone(),
            identity: auth.confirmed_identity.clone(),
            device_id,
            expected_session_generation: auth.session_generation,
            scope_fingerprint: digest_json(&scope)?,
        })
    }

    fn valid_legacy_device(
        device: &nelomai_client_api::AuthDevice,
        expected: Option<&str>,
    ) -> Result<(), BrokerError> {
        if device.id.is_empty()
            || device.id.len() > 256
            || expected.is_some_and(|expected| expected != device.id)
            || device.runtime_version.is_some()
            || device.runtime_contract_version.is_some()
            || device.runtime_slot.is_some()
            || device.session_generation.is_some()
        {
            return Err(BrokerError::IdentityMismatch);
        }
        Ok(())
    }

    pub async fn transition_source(&self) -> Result<TransitionSourceSnapshot, BrokerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let _issuance = self.issuance.lock().await;
            self.transition_source_locked().await
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    async fn transition_source_locked(&self) -> Result<TransitionSourceSnapshot, BrokerError> {
        let (ticket, access) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            if meta.pending_recovery.is_some() || meta.pending_logout.is_some() {
                return Err(BrokerError::RecoveryRequired);
            }
            if auth.confirmed_identity.is_some() {
                if meta.pending_request.is_some() {
                    return Err(BrokerError::RecoveryRequired);
                }
                return Self::transition_source_from_auth(&auth);
            }
            if let Some(pending) = &meta.pending_request {
                match pending.kind {
                    BrokerRequestKind::LegacyRefresh => return Err(BrokerError::RecoveryRequired),
                    BrokerRequestKind::LegacyBootstrap => {
                        let access = auth
                            .access_token
                            .clone()
                            .ok_or(BrokerError::RecoveryRequired)?;
                        (pending.clone(), access)
                    }
                    _ => return Err(BrokerError::RecoveryRequired),
                }
            } else if let Some(access) = auth.access_token.clone() {
                let ticket = self.begin(
                    &mut auth,
                    BrokerRequestKind::LegacyBootstrap,
                    Uuid::new_v4().to_string(),
                    None,
                    false,
                )?;
                (ticket, access)
            } else {
                drop(_state);
                self.legacy_refresh_locked(None).await?;
                let _state = self.state.lock().await;
                return Self::transition_source_from_auth(&self.load()?);
            }
        };
        self.recheck_ticket(&ticket).await?;
        let response = self.api.legacy_bootstrap_device(&access).await;
        let device = match response {
            Ok(device) => device,
            Err(ClientApiError::Api { status, code, .. })
                if status.as_u16() == 401 && code == "invalid_access_token" =>
            {
                let _state = self.state.lock().await;
                let mut auth = self.fenced(&ticket)?;
                auth.broker
                    .as_mut()
                    .ok_or(BrokerError::RecoveryRequired)?
                    .pending_request = None;
                self.store.save(&auth)?;
                drop(_state);
                self.legacy_refresh_locked(None).await?;
                let _state = self.state.lock().await;
                return Self::transition_source_from_auth(&self.load()?);
            }
            Err(error) => return Err(error.into()),
        };
        let _state = self.state.lock().await;
        let mut auth = self.fenced(&ticket)?;
        let expected = auth
            .broker
            .as_ref()
            .and_then(|meta| meta.confirmed_device_id.as_deref());
        Self::valid_legacy_device(&device, expected)?;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.confirmed_device_id = Some(device.id);
        meta.pending_request = None;
        self.store.save(&auth)?;
        Self::transition_source_from_auth(&auth)
    }

    async fn legacy_refresh_locked(
        &self,
        allowed_transition: Option<&str>,
    ) -> Result<(), BrokerError> {
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            Self::ensure_transition_issuance_allowed(&auth, allowed_transition)?;
            if meta.pending_request.is_some()
                || meta.pending_recovery.is_some()
                || meta.pending_logout.is_some()
                || auth.confirmed_identity.is_some()
            {
                return Err(BrokerError::RecoveryRequired);
            }
            let refresh = auth
                .refresh_token
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?;
            let ticket = self.begin(
                &mut auth,
                BrokerRequestKind::LegacyRefresh,
                Uuid::new_v4().to_string(),
                None,
                false,
            )?;
            (ticket, refresh)
        };
        self.recheck_ticket(&ticket).await?;
        let response = self.api.legacy_refresh(refresh).await?;
        let _state = self.state.lock().await;
        let mut auth = self.fenced(&ticket)?;
        let expected = auth
            .broker
            .as_ref()
            .and_then(|meta| meta.confirmed_device_id.as_deref());
        Self::valid_legacy_device(&response.device, expected)?;
        if response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.refresh_token.is_empty()
            || response.access_expires_in == 0
            || response.refresh_expires_in == 0
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let access_token = response.access_token;
        let refresh_token = response.refresh_token;
        if let Some(operation_id) = allowed_transition {
            let position = auth
                .broker
                .as_ref()
                .and_then(|meta| {
                    meta.transition_authorities
                        .iter()
                        .position(|authority| authority.reconcile_operation_id == operation_id)
                })
                .ok_or(BrokerError::RecoveryRequired)?;
            {
                let authority = &auth
                    .broker
                    .as_ref()
                    .ok_or(BrokerError::RecoveryRequired)?
                    .transition_authorities[position];
                if authority.dispatch_state != TransitionDispatchStateV1::InvalidAccessRejected
                    || authority.source_identity.is_some()
                    || authority.legacy_refresh_completed
                {
                    return Err(BrokerError::RecoveryRequired);
                }
                Self::match_current_transition_scope(&auth, authority)?;
            }
            auth.access_token = Some(access_token.clone());
            auth.refresh_token = Some(refresh_token.clone());
            let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
            meta.confirmed_device_id = Some(response.device.id);
            meta.pending_request = None;
            let authority = &mut meta.transition_authorities[position];
            authority.cleanup_access_proof = access_token;
            authority.resume_refresh_proof = refresh_token;
            authority.legacy_refresh_completed = true;
            authority.dispatch_state = TransitionDispatchStateV1::DispatchIntent;
            self.save_transition_write(&auth)?;
        } else {
            auth.access_token = Some(access_token);
            auth.refresh_token = Some(refresh_token);
            let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
            meta.confirmed_device_id = Some(response.device.id);
            meta.pending_request = None;
            self.store.save(&auth)?;
        }
        Ok(())
    }

    // Called only under issuance after a durable, unambiguous access rejection.
    // The cleanup operation and its source never change; only current proofs
    // rotate. A persisted pending Refresh ticket cannot be retried after loss.
    async fn refresh_bound_transition_locked(&self, operation_id: &str) -> Result<(), BrokerError> {
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            let authority = auth
                .broker
                .as_ref()
                .and_then(|meta| {
                    meta.transition_authorities
                        .iter()
                        .find(|entry| entry.reconcile_operation_id == operation_id)
                })
                .ok_or(BrokerError::RecoveryRequired)?;
            if authority.source_identity.is_none()
                || authority.dispatch_state != TransitionDispatchStateV1::InvalidAccessRejected
            {
                return Err(BrokerError::RecoveryRequired);
            }
            Self::match_current_transition_source(&auth, authority)?;
            Self::ensure_transition_issuance_allowed(&auth, Some(operation_id))?;
            let refresh = authority.resume_refresh_proof.clone();
            let ticket = self.begin(
                &mut auth,
                BrokerRequestKind::Refresh,
                Uuid::new_v4().to_string(),
                None,
                false,
            )?;
            (ticket, refresh)
        };
        self.recheck_ticket(&ticket).await?;
        let response = self.api.refresh(refresh).await?;
        let _state = self.state.lock().await;
        let mut auth = self.fenced(&ticket)?;
        let confirmed = response.device.confirmed_identity()?;
        if Some(&confirmed) != ticket.source_identity.as_ref()
            || ticket.source_device_id.as_deref() != Some(response.device.id.as_str())
            || response.token_type != "Bearer"
            || response.access_token.is_empty()
            || response.refresh_token.is_empty()
            || response.access_expires_in == 0
            || response.refresh_expires_in == 0
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let position = auth
            .broker
            .as_ref()
            .and_then(|meta| {
                meta.transition_authorities
                    .iter()
                    .position(|entry| entry.reconcile_operation_id == operation_id)
            })
            .ok_or(BrokerError::RecoveryRequired)?;
        let authority = &auth.broker.as_ref().unwrap().transition_authorities[position];
        Self::match_current_transition_scope(&auth, authority)?;
        if authority.dispatch_state != TransitionDispatchStateV1::InvalidAccessRejected {
            return Err(BrokerError::RecoveryRequired);
        }
        auth.access_token = Some(response.access_token.clone());
        auth.refresh_token = Some(response.refresh_token.clone());
        let meta = auth.broker.as_mut().unwrap();
        meta.pending_request = None;
        let authority = &mut meta.transition_authorities[position];
        authority.cleanup_access_proof = response.access_token;
        authority.resume_refresh_proof = response.refresh_token;
        authority.dispatch_state = TransitionDispatchStateV1::DispatchIntent;
        self.save_transition_write(&auth)?;
        Ok(())
    }

    pub async fn reconcile_transition(
        &self,
        frozen: FrozenReconcileRequest,
    ) -> Result<RuntimeSwitchReconcileResponse, BrokerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let _issuance = self.issuance.lock().await;
            self.reconcile_transition_locked(frozen).await
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    async fn reconcile_transition_locked(
        &self,
        frozen: FrozenReconcileRequest,
    ) -> Result<RuntimeSwitchReconcileResponse, BrokerError> {
        {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            if let Some(authority) = meta
                .transition_authorities
                .iter()
                .find(|authority| authority.reconcile_operation_id == frozen.request.operation_id)
            {
                Self::match_transition_authority(authority, &frozen)?;
                if let Some(receipt) = authority
                    .reconcile_receipt
                    .as_ref()
                    .filter(|receipt| receipt.state == "clean")
                {
                    return Self::api_receipt(receipt);
                }
            } else {
                Self::active(&auth)?;
                Self::ensure_transition_issuance_allowed(
                    &auth,
                    Some(&frozen.request.operation_id),
                )?;
                if meta.pending_request.is_some()
                    || meta.pending_recovery.is_some()
                    || meta.pending_logout.is_some()
                    || meta.transition_authorities.len() >= MAX_TRANSITION_AUTHORITIES
                {
                    return Err(BrokerError::RecoveryRequired);
                }
                let source = Self::transition_source_from_auth(&auth)?;
                if frozen.request.source_identity != source.identity
                    || frozen.request.expected_session_generation
                        != source.expected_session_generation
                    || frozen.source_device_id != source.device_id
                    || frozen.source_scope_fingerprint != source.scope_fingerprint
                {
                    return Err(BrokerError::IdentityMismatch);
                }
                let authority = TransitionAuthorityV1 {
                    schema_version: 1,
                    reconcile_operation_id: frozen.request.operation_id.clone(),
                    request_fingerprint: frozen.request_fingerprint.clone(),
                    source_auth_epoch: auth.auth_epoch,
                    source_family: meta.family.clone(),
                    source_identity: auth.confirmed_identity.clone(),
                    source_device_id: source.device_id,
                    source_scope_fingerprint: source.scope_fingerprint,
                    expected_session_generation: auth.session_generation,
                    target_identity: frozen.request.target_identity.identity(None)?,
                    cleanup_contract_version: frozen.request.cleanup_contract_version,
                    cleanup_access_proof: auth
                        .access_token
                        .clone()
                        .ok_or(BrokerError::RecoveryRequired)?,
                    resume_refresh_proof: auth
                        .refresh_token
                        .clone()
                        .ok_or(BrokerError::RecoveryRequired)?,
                    legacy_refresh_completed: false,
                    superseded_by: None,
                    dispatch_state: TransitionDispatchStateV1::Captured,
                    reconcile_receipt: None,
                    resume_ticket: None,
                    resume_evidence: None,
                };
                auth.broker
                    .as_mut()
                    .ok_or(BrokerError::RecoveryRequired)?
                    .transition_authorities
                    .push(authority);
                self.save_transition_write(&auth)?;
            }
        }

        for _ in 0..3 {
            let (authority, may_refresh, recheck_current) = {
                let _state = self.state.lock().await;
                let mut auth = self.load()?;
                let position = auth
                    .broker
                    .as_ref()
                    .and_then(|meta| {
                        meta.transition_authorities.iter().position(|authority| {
                            authority.reconcile_operation_id == frozen.request.operation_id
                        })
                    })
                    .ok_or(BrokerError::RecoveryRequired)?;
                let state = {
                    let authority = &auth
                        .broker
                        .as_ref()
                        .ok_or(BrokerError::RecoveryRequired)?
                        .transition_authorities[position];
                    Self::match_transition_authority(authority, &frozen)?;
                    authority.dispatch_state
                };
                if state == TransitionDispatchStateV1::InvalidAccessRejected {
                    let authority = &auth
                        .broker
                        .as_ref()
                        .ok_or(BrokerError::RecoveryRequired)?
                        .transition_authorities[position];
                    let bound = authority.source_identity.is_some();
                    if !bound && authority.legacy_refresh_completed {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    Self::match_current_transition_scope(&auth, authority)?;
                    if auth
                        .broker
                        .as_ref()
                        .is_some_and(|meta| meta.pending_request.is_some())
                    {
                        // A durable LegacyRefresh ticket means its rotating
                        // response is unknown. Never resend either old proof.
                        return Err(BrokerError::RecoveryRequired);
                    }
                    drop(_state);
                    if bound {
                        self.refresh_bound_transition_locked(&frozen.request.operation_id)
                            .await?;
                    } else {
                        self.legacy_refresh_locked(Some(&frozen.request.operation_id))
                            .await?;
                    }
                    let _state = self.state.lock().await;
                    let auth = self.load()?;
                    let position = auth
                        .broker
                        .as_ref()
                        .and_then(|meta| {
                            meta.transition_authorities.iter().position(|authority| {
                                authority.reconcile_operation_id == frozen.request.operation_id
                            })
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    {
                        let entry = &auth
                            .broker
                            .as_ref()
                            .ok_or(BrokerError::RecoveryRequired)?
                            .transition_authorities[position];
                        Self::match_transition_authority(entry, &frozen)?;
                        Self::match_current_transition_scope(&auth, entry)?;
                    }
                    let entry = &auth
                        .broker
                        .as_ref()
                        .ok_or(BrokerError::RecoveryRequired)?
                        .transition_authorities[position];
                    if (!bound && !entry.legacy_refresh_completed)
                        || entry.dispatch_state != TransitionDispatchStateV1::DispatchIntent
                    {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    let authority = entry.clone();
                    (authority, false, true)
                } else {
                    let recheck_current = state == TransitionDispatchStateV1::Captured;
                    if recheck_current {
                        let authority = &auth
                            .broker
                            .as_ref()
                            .ok_or(BrokerError::RecoveryRequired)?
                            .transition_authorities[position];
                        Self::match_current_transition_source(&auth, authority)?;
                    }
                    let authority = &mut auth
                        .broker
                        .as_mut()
                        .ok_or(BrokerError::RecoveryRequired)?
                        .transition_authorities[position];
                    let may_refresh = (recheck_current
                        || state == TransitionDispatchStateV1::ResponseKnown)
                        && (authority.source_identity.is_some()
                            || !authority.legacy_refresh_completed);
                    if authority
                        .reconcile_receipt
                        .as_ref()
                        .is_some_and(|receipt| receipt.state != "retry")
                    {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    authority.reconcile_receipt = None;
                    authority.dispatch_state = TransitionDispatchStateV1::DispatchIntent;
                    let authority = authority.clone();
                    self.save_transition_write(&auth)?;
                    (authority, may_refresh, recheck_current)
                }
            };
            if recheck_current {
                let _state = self.state.lock().await;
                let auth = self.load()?;
                Self::match_current_transition_source(&auth, &authority)?;
            }
            let result = if let Some(identity) = &authority.source_identity {
                let snapshot = AccessSnapshot::new(
                    authority.cleanup_access_proof.clone(),
                    identity.clone(),
                    authority.source_auth_epoch,
                    authority.source_family.clone(),
                )?;
                self.api
                    .clone()
                    .with_captured_source(&snapshot)?
                    .reconcile_runtime_switch(snapshot.access_token(), &frozen.request)
                    .await
            } else {
                self.api
                    .reconcile_runtime_switch(&authority.cleanup_access_proof, &frozen.request)
                    .await
            };
            match result {
                Ok(receipt) => {
                    let _state = self.state.lock().await;
                    let mut auth = self.load()?;
                    let authority = auth
                        .broker
                        .as_mut()
                        .and_then(|meta| {
                            meta.transition_authorities.iter_mut().find(|authority| {
                                authority.reconcile_operation_id == frozen.request.operation_id
                            })
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    Self::match_transition_authority(authority, &frozen)?;
                    authority.dispatch_state = TransitionDispatchStateV1::ResponseKnown;
                    authority.reconcile_receipt = Some(Self::stored_receipt(&receipt));
                    self.save_transition_write(&auth)?;
                    return Ok(receipt);
                }
                Err(ClientApiError::Api { status, code, .. })
                    if may_refresh && status.as_u16() == 401 && code == "invalid_access_token" =>
                {
                    let _state = self.state.lock().await;
                    let mut auth = self.load()?;
                    let entry = auth
                        .broker
                        .as_mut()
                        .and_then(|meta| {
                            meta.transition_authorities.iter_mut().find(|entry| {
                                entry.reconcile_operation_id == frozen.request.operation_id
                            })
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    entry.dispatch_state = TransitionDispatchStateV1::InvalidAccessRejected;
                    self.save_transition_write(&auth)?;
                }
                Err(ClientApiError::Api { status, code, .. })
                    if status.as_u16() == 401 && code == "invalid_access_token" =>
                {
                    let _state = self.state.lock().await;
                    let mut auth = self.load()?;
                    let entry = auth
                        .broker
                        .as_mut()
                        .and_then(|meta| {
                            meta.transition_authorities.iter_mut().find(|entry| {
                                entry.reconcile_operation_id == frozen.request.operation_id
                            })
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    // An uncertain dispatch stays uncertain even after its
                    // old proof expires. A later 401 cannot prove no commit.
                    entry.dispatch_state = TransitionDispatchStateV1::OutcomeUnknown;
                    self.save_transition_write(&auth)?;
                    return Err(BrokerError::RecoveryRequired);
                }
                Err(error) => {
                    let _state = self.state.lock().await;
                    let mut auth = self.load()?;
                    let entry = auth
                        .broker
                        .as_mut()
                        .and_then(|meta| {
                            meta.transition_authorities.iter_mut().find(|entry| {
                                entry.reconcile_operation_id == frozen.request.operation_id
                            })
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    entry.dispatch_state = TransitionDispatchStateV1::OutcomeUnknown;
                    self.save_transition_write(&auth)?;
                    return Err(error.into());
                }
            }
        }
        Err(BrokerError::RecoveryRequired)
    }

    pub async fn supersede_transition(
        &self,
        operation_id: &str,
        predecessor: FrozenReconcileRequest,
        target: RuntimeTarget,
    ) -> Result<RuntimeSupersedeResponse, BrokerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let _issuance = self.issuance.lock().await;
            self.supersede_transition_locked(operation_id, predecessor, target)
                .await
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    async fn supersede_transition_locked(
        &self,
        operation_id: &str,
        predecessor: FrozenReconcileRequest,
        target: RuntimeTarget,
    ) -> Result<RuntimeSupersedeResponse, BrokerError> {
        let canonical =
            Uuid::parse_str(operation_id).is_ok_and(|parsed| parsed.to_string() == operation_id);
        target.identity(None)?;
        if !canonical {
            return Err(BrokerError::RecoveryRequired);
        }
        let ticket = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            let current = Self::transition_source_from_auth(&auth)?;
            if current.identity.is_none() {
                return Err(BrokerError::RecoveryRequired);
            }
            let authority = auth
                .broker
                .as_ref()
                .and_then(|meta| {
                    meta.transition_authorities.iter().find(|authority| {
                        authority.reconcile_operation_id == predecessor.request.operation_id
                    })
                })
                .ok_or(BrokerError::RecoveryRequired)?;
            Self::match_transition_authority(authority, &predecessor)?;
            if authority
                .reconcile_receipt
                .as_ref()
                .is_none_or(|receipt| receipt.state != "clean")
                || (authority.source_identity.as_ref() != current.identity.as_ref()
                    && authority
                        .resume_evidence
                        .as_ref()
                        .map(|evidence| &evidence.identity)
                        != current.identity.as_ref())
            {
                return Err(BrokerError::RecoveryRequired);
            }
            let source = RuntimeLogoutSourceV1 {
                auth_epoch: current.auth_epoch,
                family: current.family,
                identity: current.identity,
                device_id: current.device_id,
                scope_fingerprint: current.scope_fingerprint,
            };
            let expected = PendingRuntimeSupersedeV1 {
                operation_id: operation_id.into(),
                superseded_reconcile_operation_id: predecessor.request.operation_id.clone(),
                expected_session_generation: source
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.session_generation),
                target_identity: target.identity(None)?,
                source,
                refresh_proof: auth
                    .refresh_token
                    .clone()
                    .ok_or(BrokerError::RecoveryRequired)?,
                response_state: None,
                response_reconcile_operation_id: None,
                retry_after_seconds: None,
            };
            match auth.pending_runtime_supersede.clone() {
                Some(saved) => {
                    let mut request_only = saved.clone();
                    request_only.response_state = None;
                    request_only.response_reconcile_operation_id = None;
                    request_only.retry_after_seconds = None;
                    if request_only != expected {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    if let (Some(state), Some(reconcile_operation_id)) = (
                        saved.response_state.as_deref(),
                        saved.response_reconcile_operation_id.as_ref(),
                    ) {
                        if state == "clean" {
                            return Ok(RuntimeSupersedeResponse {
                                state: RuntimeSwitchState::Clean,
                                reconcile_operation_id: reconcile_operation_id.clone(),
                                retry_after_seconds: saved.retry_after_seconds,
                            });
                        }
                        if state != "retry" {
                            return Err(BrokerError::RecoveryRequired);
                        }
                        auth.pending_runtime_supersede = Some(request_only.clone());
                        self.save_transition_write(&auth)?;
                        request_only
                    } else {
                        saved
                    }
                }
                None => {
                    auth.pending_runtime_supersede = Some(expected.clone());
                    self.save_transition_write(&auth)?;
                    expected
                }
            }
        };
        let request = RuntimeSupersedeRequest {
            refresh_token: ticket.refresh_proof.clone(),
            operation_id: ticket.operation_id.clone(),
            superseded_reconcile_operation_id: ticket.superseded_reconcile_operation_id.clone(),
            expected_session_generation: ticket.expected_session_generation,
            target_identity: target.clone(),
        };
        let response = self.api.supersede_runtime(&request).await?;
        if (response.state == RuntimeSwitchState::Retry
            && response.reconcile_operation_id != ticket.superseded_reconcile_operation_id)
            || (response.state == RuntimeSwitchState::Clean
                && response.reconcile_operation_id == ticket.superseded_reconcile_operation_id)
        {
            return Err(BrokerError::IdentityMismatch);
        }
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        if auth.pending_runtime_supersede.as_ref() != Some(&ticket) {
            return Err(BrokerError::Cancelled);
        }
        let current = Self::transition_source_from_auth(&auth)?;
        if current.auth_epoch != ticket.source.auth_epoch
            || current.family != ticket.source.family
            || current.identity != ticket.source.identity
            || current.device_id != ticket.source.device_id
            || current.scope_fingerprint != ticket.source.scope_fingerprint
        {
            return Err(BrokerError::Cancelled);
        }
        if response.state == RuntimeSwitchState::Clean {
            let mut request = predecessor.request.clone();
            request.operation_id = response.reconcile_operation_id.clone();
            request.source_identity = current.identity.clone();
            request.expected_session_generation = current.expected_session_generation;
            request.target_identity = target.clone();
            let successor = FrozenReconcileRequest::new(request, &current)?;
            let source_identity = current.identity.clone();
            let cleanup_access_proof = auth
                .access_token
                .clone()
                .ok_or(BrokerError::RecoveryRequired)?;
            let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
            if meta.transition_authorities.len() >= MAX_TRANSITION_AUTHORITIES {
                return Err(BrokerError::RecoveryRequired);
            }
            let predecessor_authority = meta
                .transition_authorities
                .iter_mut()
                .find(|authority| {
                    authority.reconcile_operation_id == ticket.superseded_reconcile_operation_id
                })
                .ok_or(BrokerError::RecoveryRequired)?;
            predecessor_authority.superseded_by = Some(response.reconcile_operation_id.clone());
            meta.transition_authorities.push(TransitionAuthorityV1 {
                schema_version: 1,
                reconcile_operation_id: response.reconcile_operation_id.clone(),
                request_fingerprint: successor.request_fingerprint,
                source_auth_epoch: current.auth_epoch,
                source_family: current.family.clone(),
                source_identity,
                source_device_id: current.device_id,
                source_scope_fingerprint: current.scope_fingerprint,
                expected_session_generation: current.expected_session_generation,
                target_identity: target.identity(None)?,
                cleanup_contract_version: predecessor.request.cleanup_contract_version,
                cleanup_access_proof,
                resume_refresh_proof: ticket.refresh_proof.clone(),
                legacy_refresh_completed: false,
                superseded_by: None,
                dispatch_state: TransitionDispatchStateV1::ResponseKnown,
                reconcile_receipt: Some(TransitionReconcileReceiptV1 {
                    state: "clean".into(),
                    operation_id: response.reconcile_operation_id.clone(),
                    retired_lease_ids: Vec::new(),
                    retired_session_ids: Vec::new(),
                    retired_operation_ids: Vec::new(),
                    retry_after_seconds: None,
                }),
                resume_ticket: None,
                resume_evidence: None,
            });
        }
        let saved = auth
            .pending_runtime_supersede
            .as_mut()
            .ok_or(BrokerError::RecoveryRequired)?;
        saved.response_state = Some(
            match response.state {
                RuntimeSwitchState::Clean => "clean",
                RuntimeSwitchState::Retry => "retry",
            }
            .into(),
        );
        saved.response_reconcile_operation_id = Some(response.reconcile_operation_id.clone());
        saved.retry_after_seconds = response.retry_after_seconds;
        self.save_transition_write(&auth)?;
        Ok(response)
    }

    pub async fn finish_supersede(
        &self,
        operation_id: &str,
        reconcile_operation_id: &str,
    ) -> Result<(), BrokerError> {
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        let Some(ticket) = auth.pending_runtime_supersede.as_ref() else {
            return Ok(());
        };
        if ticket.operation_id != operation_id
            || ticket.response_state.as_deref() != Some("clean")
            || ticket.response_reconcile_operation_id.as_deref() != Some(reconcile_operation_id)
        {
            return Err(BrokerError::RecoveryRequired);
        }
        auth.pending_runtime_supersede = None;
        self.save_transition_write(&auth)
    }

    /// Reconstruct only the active request's source from protected provenance.
    /// The public cleanup IDs/target must still reproduce the exact saved hash.
    pub(crate) async fn restore_transition_request(
        &self,
        mut request: RuntimeSwitchReconcileRequest,
        fingerprint: &str,
    ) -> Result<FrozenReconcileRequest, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        let authority = auth
            .broker
            .as_ref()
            .and_then(|meta| {
                meta.transition_authorities
                    .iter()
                    .find(|authority| authority.reconcile_operation_id == request.operation_id)
            })
            .ok_or(BrokerError::RecoveryRequired)?;
        request.source_identity = authority.source_identity.clone();
        request.expected_session_generation = authority.expected_session_generation;
        let frozen = FrozenReconcileRequest::from_persisted(
            request,
            authority.source_device_id.clone(),
            authority.source_scope_fingerprint.clone(),
            Some(fingerprint),
        )?;
        Self::match_transition_authority(authority, &frozen)?;
        Ok(frozen)
    }

    fn match_transition_authority(
        authority: &TransitionAuthorityV1,
        frozen: &FrozenReconcileRequest,
    ) -> Result<(), BrokerError> {
        if authority.request_fingerprint != frozen.request_fingerprint
            || authority.source_identity != frozen.request.source_identity
            || authority.source_device_id != frozen.source_device_id
            || authority.source_scope_fingerprint != frozen.source_scope_fingerprint
            || authority.expected_session_generation != frozen.request.expected_session_generation
            || authority.target_identity != frozen.request.target_identity.identity(None)?
            || authority.cleanup_contract_version != frozen.request.cleanup_contract_version
        {
            return Err(BrokerError::IdentityMismatch);
        }
        Ok(())
    }

    fn match_current_transition_source(
        auth: &AuthStoreV1,
        authority: &TransitionAuthorityV1,
    ) -> Result<(), BrokerError> {
        Self::match_current_transition_scope(auth, authority)?;
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if meta.pending_request.is_some()
            || meta.pending_recovery.is_some()
            || meta.pending_logout.is_some()
            || auth.access_token.as_deref() != Some(authority.cleanup_access_proof.as_str())
            || auth.refresh_token.as_deref() != Some(authority.resume_refresh_proof.as_str())
        {
            return Err(BrokerError::Cancelled);
        }
        Ok(())
    }

    fn match_current_transition_scope(
        auth: &AuthStoreV1,
        authority: &TransitionAuthorityV1,
    ) -> Result<(), BrokerError> {
        Self::active(auth)?;
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if auth.auth_epoch != authority.source_auth_epoch
            || meta.family != authority.source_family
            || auth.confirmed_identity != authority.source_identity
            || meta.confirmed_device_id.as_deref() != Some(authority.source_device_id.as_str())
            || auth.session_generation != authority.expected_session_generation
        {
            return Err(BrokerError::Cancelled);
        }
        Ok(())
    }

    fn ensure_transition_issuance_allowed(
        auth: &AuthStoreV1,
        allowed_transition: Option<&str>,
    ) -> Result<(), BrokerError> {
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if meta.transition_authorities.iter().any(|authority| {
            authority.resume_evidence.is_none()
                && authority.superseded_by.is_none()
                && auth.auth_epoch == authority.source_auth_epoch
                && meta.family == authority.source_family
                && auth.confirmed_identity == authority.source_identity
                && meta.confirmed_device_id.as_deref() == Some(authority.source_device_id.as_str())
                && auth.session_generation == authority.expected_session_generation
                && allowed_transition != Some(authority.reconcile_operation_id.as_str())
        }) {
            return Err(BrokerError::RecoveryRequired);
        }
        Ok(())
    }

    fn stored_receipt(receipt: &RuntimeSwitchReconcileResponse) -> TransitionReconcileReceiptV1 {
        TransitionReconcileReceiptV1 {
            state: match receipt.state {
                RuntimeSwitchState::Clean => "clean",
                RuntimeSwitchState::Retry => "retry",
            }
            .into(),
            operation_id: receipt.operation_id.clone(),
            retired_lease_ids: receipt.retired_lease_ids.clone(),
            retired_session_ids: receipt.retired_session_ids.clone(),
            retired_operation_ids: receipt.retired_operation_ids.clone(),
            retry_after_seconds: receipt.retry_after_seconds,
        }
    }

    fn api_receipt(
        receipt: &TransitionReconcileReceiptV1,
    ) -> Result<RuntimeSwitchReconcileResponse, BrokerError> {
        Ok(RuntimeSwitchReconcileResponse {
            state: match receipt.state.as_str() {
                "clean" => RuntimeSwitchState::Clean,
                "retry" => RuntimeSwitchState::Retry,
                _ => return Err(BrokerError::RecoveryRequired),
            },
            operation_id: receipt.operation_id.clone(),
            retired_lease_ids: receipt.retired_lease_ids.clone(),
            retired_session_ids: receipt.retired_session_ids.clone(),
            retired_operation_ids: receipt.retired_operation_ids.clone(),
            retry_after_seconds: receipt.retry_after_seconds,
        })
    }

    fn transition_resume_target(
        authority: &TransitionAuthorityV1,
        decision: &str,
    ) -> Result<nelomai_contracts::RuntimeIdentity, BrokerError> {
        match decision {
            "apply" => Ok(authority.target_identity.clone()),
            "cancel" => Ok(nelomai_contracts::RuntimeIdentity {
                session_generation: None,
                ..authority
                    .source_identity
                    .clone()
                    .ok_or(BrokerError::IdentityMismatch)?
            }),
            _ => Err(BrokerError::RecoveryRequired),
        }
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

    async fn recheck_ticket(&self, ticket: &BrokerRequestV1) -> Result<(), BrokerError> {
        let _state = self.state.lock().await;
        self.fenced(ticket)?;
        Ok(())
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
        self.observe_stamped()
            .await
            .map(|(_, observation)| observation)
    }

    pub async fn observe_stamped(&self) -> Result<(ScopeStamp, BrokerObservation), BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        let state = Self::observed_state(&auth)?;
        let access = if state == BrokerAuthState::Active {
            Self::snapshot(&auth).ok()
        } else {
            None
        };
        Ok((
            ScopeStamp::of(&auth)?,
            BrokerObservation {
                state: if state == BrokerAuthState::Active && access.is_none() {
                    BrokerAuthState::RecoveryRequired
                } else {
                    state
                },
                access,
            },
        ))
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
        let fence = self.capture_login_fence().await?;
        self.login_fenced(request, target, &fence).await
    }

    pub(crate) async fn capture_login_fence(&self) -> Result<LoginFence, BrokerError> {
        self.capture_stamped_login_fence(None).await
    }

    pub(crate) async fn capture_stamped_login_fence(
        &self,
        stamp: Option<&ScopeStamp>,
    ) -> Result<LoginFence, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        if let Some(stamp) = stamp {
            stamp.check(&auth)?;
        }
        Ok(LoginFence {
            epoch: auth.auth_epoch,
            family: auth
                .broker
                .as_ref()
                .ok_or(BrokerError::RecoveryRequired)?
                .family
                .clone(),
        })
    }

    pub(crate) async fn with_current_access<T>(
        &self,
        access: &AccessSnapshot,
        bind: impl FnOnce() -> Result<T, BrokerError>,
    ) -> Result<T, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        Self::active(&auth)?;
        if Self::snapshot(&auth)? != *access {
            return Err(BrokerError::Cancelled);
        }
        // No await between validating owner provenance and the synchronous
        // runtime write; logout cannot interleave a stale cache binding.
        bind()
    }

    pub(crate) async fn login_fenced(
        &self,
        request: &LoginRequest,
        target: &RuntimeTarget,
        fence: &LoginFence,
    ) -> Result<AccessSnapshot, BrokerError> {
        self.login_fenced_with_ticket(request, target, fence, || Ok(()), |_| {})
            .await
    }

    pub(crate) async fn login_fenced_with_ticket(
        &self,
        request: &LoginRequest,
        target: &RuntimeTarget,
        fence: &LoginFence,
        check_request: impl Fn() -> Result<(), BrokerError> + Send,
        on_ticket: impl FnOnce(&BrokerRequestV1) + Send,
    ) -> Result<AccessSnapshot, BrokerError> {
        target.identity(None)?;
        let _issuance = self.issuance.lock().await;
        let (ticket, request) = {
            let _state = self.state.lock().await;
            check_request()?;
            let mut auth = self.load()?;
            let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
            if auth.auth_epoch != fence.epoch || meta.family != fence.family {
                return Err(BrokerError::Cancelled);
            }
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
            on_ticket(&ticket);
            let mut request = request.clone();
            request.install_secret = auth.install_secret;
            (ticket, request)
        };
        let stop = self.stop.stop_local().await.and_then(|()| check_request());
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
                source: None,
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
        // Only accepted login is proof that the prior delivery intent was
        // superseded; failed/unknown password attempts retain the cleanup marker.
        meta.pending_push_cleanup_epoch = None;
        self.store.save(&auth)?;
        Self::snapshot(&auth)
    }

    pub async fn access_token(
        &self,
        stale: Option<&AccessSnapshot>,
    ) -> Result<AccessSnapshot, BrokerError> {
        self.access_token_inner(None, stale, || Ok(())).await
    }

    pub async fn access_token_fenced(
        &self,
        stamp: &ScopeStamp,
        stale: Option<&AccessSnapshot>,
    ) -> Result<AccessSnapshot, BrokerError> {
        self.access_token_fenced_checked(stamp, stale, || Ok(()))
            .await
    }

    pub(crate) async fn access_token_fenced_checked(
        &self,
        stamp: &ScopeStamp,
        stale: Option<&AccessSnapshot>,
        check_request: impl FnOnce() -> Result<(), BrokerError>,
    ) -> Result<AccessSnapshot, BrokerError> {
        self.access_token_inner(Some(stamp), stale, check_request)
            .await
    }

    async fn access_token_inner(
        &self,
        stamp: Option<&ScopeStamp>,
        stale: Option<&AccessSnapshot>,
        check_request: impl FnOnce() -> Result<(), BrokerError>,
    ) -> Result<AccessSnapshot, BrokerError> {
        {
            let _state = self.state.lock().await;
            let auth = self.load()?;
            if let Some(stamp) = stamp {
                stamp.check(&auth)?;
            }
            Self::active(&auth)?;
            Self::ensure_transition_issuance_allowed(&auth, None)?;
        }
        let _issuance = self.issuance.lock().await;
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            check_request()?;
            let mut auth = self.load()?;
            if let Some(stamp) = stamp {
                stamp.check(&auth)?;
            }
            Self::active(&auth)?;
            Self::ensure_transition_issuance_allowed(&auth, None)?;
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
            || ticket.source_device_id.as_deref() != Some(response.device.id.as_str())
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
        self.resume_inner(args, None).await
    }

    async fn resume_inner(
        &self,
        args: ResumeArguments,
        transition_operation_id: Option<&str>,
    ) -> Result<AccessSnapshot, BrokerError> {
        let stored = args.stored()?;
        let _issuance = self.issuance.lock().await;
        let (ticket, refresh) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            Self::active(&auth)?;
            Self::ensure_transition_issuance_allowed(&auth, transition_operation_id)?;
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
            operation_id: args.operation_id.clone(),
            expected_session_generation: args.expected_session_generation,
            target_identity: args.target.clone(),
            reconcile_operation_id: args.reconcile_operation_id.clone(),
            decision: args.decision.clone(),
        };
        self.recheck_ticket(&ticket).await?;
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
        auth.access_token = Some(response.access_token.clone());
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        // Resume invalidates ordinary background scope, unlike ordinary refresh.
        meta.family = Uuid::new_v4().to_string();
        meta.pending_recovery = None;
        meta.completed_resume = Some(CompletedResumeV1 {
            request: ticket.clone(),
            identity: response.identity.clone(),
        });
        meta.pending_request = None;
        if let Some(operation_id) = transition_operation_id {
            let authority = meta
                .transition_authorities
                .iter_mut()
                .find(|authority| authority.reconcile_operation_id == operation_id)
                .ok_or(BrokerError::RecoveryRequired)?;
            authority.resume_ticket = Some(ticket);
            authority.resume_evidence = Some(TransitionResumeEvidenceV1 {
                operation_id: args.operation_id,
                reconcile_operation_id: args.reconcile_operation_id,
                decision: args.decision,
                target_identity: args.target.identity(None)?,
                identity: response.identity,
                access_token: response.access_token,
                token_type: response.token_type,
                access_expires_in: response.access_expires_in,
            });
            self.save_transition_write(&auth)?;
        } else {
            self.store.save(&auth)?;
        }
        Self::snapshot(&auth)
    }

    /// Transition-only resume wrapper. It requires the exact protected clean
    /// reconcile receipt and archives the existing broker resume ticket/result.
    pub async fn resume_transition(
        &self,
        args: ResumeArguments,
    ) -> Result<TransitionResumeReceipt, BrokerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let historical = {
                let _state = self.state.lock().await;
                let auth = self.load()?;
                let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
                let authority = meta
                    .transition_authorities
                    .iter()
                    .find(|authority| {
                        authority.reconcile_operation_id == args.reconcile_operation_id
                    })
                    .ok_or(BrokerError::RecoveryRequired)?;
                let expected_target = Self::transition_resume_target(authority, &args.decision)?;
                if authority
                    .reconcile_receipt
                    .as_ref()
                    .is_none_or(|receipt| receipt.state != "clean")
                    || authority.source_device_id.is_empty()
                    || authority.expected_session_generation != args.expected_session_generation
                    || expected_target != args.target.identity(None)?
                {
                    return Err(BrokerError::IdentityMismatch);
                }
                if let Some(evidence) = &authority.resume_evidence {
                    if evidence.operation_id != args.operation_id
                        || evidence.reconcile_operation_id != args.reconcile_operation_id
                        || evidence.decision != args.decision
                        || evidence.target_identity != expected_target
                    {
                        return Err(BrokerError::Cancelled);
                    }
                    let current_access = if meta.completed_resume.as_ref().is_some_and(|done| {
                        done.request.operation_id == args.operation_id
                            && done.identity == evidence.identity
                    }) && auth.confirmed_identity.as_ref()
                        == Some(&evidence.identity)
                        && auth.access_token.as_deref() == Some(evidence.access_token.as_str())
                    {
                        Some(Self::snapshot(&auth)?)
                    } else {
                        None
                    };
                    return Ok(TransitionResumeReceipt {
                        identity: evidence.identity.clone(),
                        current_access,
                    });
                }
                let source_is_current = authority.source_auth_epoch == auth.auth_epoch
                    && authority.source_family == meta.family
                    && authority.source_identity == auth.confirmed_identity
                    && meta.confirmed_device_id.as_deref()
                        == Some(authority.source_device_id.as_str());
                if source_is_current {
                    None
                } else {
                    let ticket = authority
                        .resume_ticket
                        .clone()
                        .ok_or(BrokerError::IdentityMismatch)?;
                    if ticket.operation_id != args.operation_id
                        || ticket.resume.as_ref() != Some(&args.stored()?)
                    {
                        return Err(BrokerError::Cancelled);
                    }
                    Some((ticket, authority.resume_refresh_proof.clone()))
                }
            };
            if let Some((ticket, refresh)) = historical {
                return self.resume_historical(&args, ticket, refresh).await;
            }
            let reconcile_operation_id = args.reconcile_operation_id.clone();
            let access = self
                .resume_inner(args, Some(&reconcile_operation_id))
                .await?;
            Ok(TransitionResumeReceipt {
                identity: access.identity().clone(),
                current_access: Some(access),
            })
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    async fn resume_historical(
        &self,
        args: &ResumeArguments,
        ticket: BrokerRequestV1,
        refresh: String,
    ) -> Result<TransitionResumeReceipt, BrokerError> {
        let _issuance = self.issuance.lock().await;
        {
            let _state = self.state.lock().await;
            let auth = self.load()?;
            let authority = auth
                .broker
                .as_ref()
                .and_then(|meta| {
                    meta.transition_authorities.iter().find(|authority| {
                        authority.reconcile_operation_id == args.reconcile_operation_id
                    })
                })
                .ok_or(BrokerError::RecoveryRequired)?;
            if authority.resume_ticket.as_ref() != Some(&ticket)
                || authority.resume_evidence.is_some()
            {
                return Err(BrokerError::Cancelled);
            }
        }
        let request = RuntimeResumeRequest {
            refresh_token: refresh,
            operation_id: args.operation_id.clone(),
            expected_session_generation: args.expected_session_generation,
            target_identity: args.target.clone(),
            reconcile_operation_id: args.reconcile_operation_id.clone(),
            decision: args.decision.clone(),
        };
        let response = self.api.resume_runtime(&request).await?;
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
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        let authority = auth
            .broker
            .as_mut()
            .and_then(|meta| {
                meta.transition_authorities.iter_mut().find(|authority| {
                    authority.reconcile_operation_id == args.reconcile_operation_id
                })
            })
            .ok_or(BrokerError::RecoveryRequired)?;
        if authority.resume_ticket.as_ref() != Some(&ticket) || authority.resume_evidence.is_some()
        {
            return Err(BrokerError::Cancelled);
        }
        authority.resume_evidence = Some(TransitionResumeEvidenceV1 {
            operation_id: args.operation_id.clone(),
            reconcile_operation_id: args.reconcile_operation_id.clone(),
            decision: args.decision.clone(),
            target_identity: args.target.identity(None)?,
            identity: response.identity.clone(),
            access_token: response.access_token,
            token_type: response.token_type,
            access_expires_in: response.access_expires_in,
        });
        self.save_transition_write(&auth)?;
        Ok(TransitionResumeReceipt {
            identity: response.identity,
            current_access: None,
        })
    }

    /// Host-only, after durable native cleanup handoff; never runtime IPC.
    pub async fn stage_push_cleanup(&self, epoch: u64) -> Result<(), BrokerError> {
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        if auth.auth_epoch != epoch
            || (auth.logout_state != LogoutState::Pending
                && !(auth.logout_state == LogoutState::LoggedOut
                    && meta.pending_push_cleanup_epoch == Some(epoch)))
        {
            return Err(BrokerError::Cancelled);
        }
        meta.pending_push_cleanup_epoch = Some(epoch);
        self.store.save(&auth)?;
        Ok(())
    }

    pub async fn pending_push_cleanup(&self) -> Result<Option<u64>, BrokerError> {
        let _state = self.state.lock().await;
        Ok(self
            .load()?
            .broker
            .ok_or(BrokerError::RecoveryRequired)?
            .pending_push_cleanup_epoch)
    }

    pub async fn push_cleanup_is_current(&self, epoch: u64) -> Result<bool, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        // This durable handoff is independent of a later login attempt's epoch
        // and state. Only accepted login or a newer cleanup supersedes it.
        Ok(auth
            .broker
            .as_ref()
            .and_then(|meta| meta.pending_push_cleanup_epoch)
            == Some(epoch))
    }

    pub async fn finish_push_cleanup(&self, epoch: u64) -> Result<(), BrokerError> {
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        if meta.pending_push_cleanup_epoch.is_none() {
            return Ok(());
        }
        if meta.pending_push_cleanup_epoch != Some(epoch) {
            return Err(BrokerError::Cancelled);
        }
        meta.pending_push_cleanup_epoch = None;
        self.store.save(&auth)?;
        Ok(())
    }

    pub async fn logout(&self) -> Result<(), BrokerError> {
        self.logout_inner(None, None, || {}).await
    }

    /// The callback is synchronous and runs under the same state lock as the
    /// durable epoch mutation. Remote owners enqueue revoke here, never await I/O.
    pub async fn logout_fenced(
        &self,
        stamp: &ScopeStamp,
        revoke: impl FnOnce() + Send,
    ) -> Result<(), BrokerError> {
        self.logout_inner(Some(stamp), None, revoke).await
    }

    /// Owner-resolved per-peer intent only; protected tickets never cross IPC.
    pub(crate) async fn logout_pending_login_fenced(
        &self,
        stamp: &ScopeStamp,
        pending: Option<&BrokerRequestV1>,
    ) -> Result<(), BrokerError> {
        self.logout_inner(Some(stamp), pending, || {}).await
    }

    async fn logout_inner(
        &self,
        stamp: Option<&ScopeStamp>,
        pending_login: Option<&BrokerRequestV1>,
        revoke: impl FnOnce() + Send,
    ) -> Result<(), BrokerError> {
        // Deliberately never acquire issuance: a hung refresh/resume cannot
        // delay the durable cancellation fence, local stop, or family revocation.
        let (epoch, proof) = {
            let _state = self.state.lock().await;
            let mut auth = self.load()?;
            if let Some(stamp) = stamp {
                if stamp.check(&auth).is_err() {
                    let ticket = pending_login.ok_or(BrokerError::Cancelled)?;
                    if ticket.kind != BrokerRequestKind::Login
                        || !Self::owns_ticket(&auth, ticket)
                        || stamp.epoch.checked_add(1) != Some(ticket.auth_epoch)
                        || stamp.identity != ticket.source_identity
                        || auth
                            .broker
                            .as_ref()
                            .is_none_or(|meta| meta.family != stamp.family)
                    {
                        return Err(BrokerError::Cancelled);
                    }
                }
            }
            if auth.logout_state == LogoutState::LoggedOut {
                // Even repeated logout cancels requests that started waiting
                // while already signed out; it must not reopen that old login.
                auth.auth_epoch = auth
                    .auth_epoch
                    .checked_add(1)
                    .ok_or(BrokerError::RecoveryRequired)?;
                let epoch = auth.auth_epoch;
                let pending_push = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
                let retry_push = pending_push.pending_push_cleanup_epoch.is_some();
                if retry_push {
                    // Repeated cancellation supersedes queued login, not the
                    // still-unfinished push cleanup of this logged-out owner.
                    pending_push.pending_push_cleanup_epoch = Some(epoch);
                }
                self.store.save(&auth)?;
                self.stop.revoke_runtime();
                revoke();
                drop(_state);
                if retry_push {
                    let (stop, handoff) = tokio::join!(
                        tokio::time::timeout(REQUEST_TIMEOUT, self.stop.stop_local()),
                        tokio::time::timeout(REQUEST_TIMEOUT, self.stop.prepare_revocation(epoch))
                    );
                    handoff.map_err(|_| BrokerError::Timeout)??;
                    return stop.map_err(|_| BrokerError::Timeout)?;
                }
                return tokio::time::timeout(REQUEST_TIMEOUT, self.stop.stop_local())
                    .await
                    .map_err(|_| BrokerError::Timeout)?;
            }
            if auth.logout_state == LogoutState::Active {
                let logout_source = Self::transition_source_from_auth(&auth).ok().map(|source| {
                    RuntimeLogoutSourceV1 {
                        auth_epoch: source.auth_epoch,
                        family: source.family,
                        identity: source.identity,
                        device_id: source.device_id,
                        scope_fingerprint: source.scope_fingerprint,
                    }
                });
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
                    self.stop.revoke_runtime();
                    revoke();
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
                if let Some(ticket) = meta
                    .pending_request
                    .as_ref()
                    .filter(|ticket| ticket.kind == BrokerRequestKind::Resume)
                    .cloned()
                {
                    let resume = ticket
                        .resume
                        .as_ref()
                        .ok_or(BrokerError::RecoveryRequired)?;
                    let authority = meta
                        .transition_authorities
                        .iter_mut()
                        .find(|authority| {
                            authority.reconcile_operation_id == resume.reconcile_operation_id
                        })
                        .ok_or(BrokerError::RecoveryRequired)?;
                    if authority.source_auth_epoch != ticket.auth_epoch
                        || authority.source_identity != ticket.source_identity
                        || ticket.source_device_id.as_deref()
                            != Some(authority.source_device_id.as_str())
                        || authority
                            .resume_ticket
                            .as_ref()
                            .is_some_and(|saved| saved != &ticket)
                    {
                        return Err(BrokerError::RecoveryRequired);
                    }
                    authority.resume_ticket = Some(ticket);
                }
                meta.pending_request = None;
                meta.pending_recovery = None;
                meta.pending_logout =
                    auth.refresh_token
                        .clone()
                        .map(|refresh_proof| PendingLogoutV1 {
                            operation_id: Uuid::new_v4().to_string(),
                            refresh_proof,
                            source: logout_source,
                        });
                self.store.save(&auth)?;
            }
            self.stop.revoke_runtime();
            revoke();
            (
                auth.auth_epoch,
                auth.broker.as_ref().and_then(|m| m.pending_logout.clone()),
            )
        };
        let Some(proof) = proof else {
            let (stop, handoff) = tokio::join!(
                tokio::time::timeout(REQUEST_TIMEOUT, self.stop.stop_local()),
                tokio::time::timeout(REQUEST_TIMEOUT, self.stop.prepare_revocation(epoch))
            );
            stop.map_err(|_| BrokerError::Timeout)??;
            handoff.map_err(|_| BrokerError::Timeout)??;
            return Err(BrokerError::AuthenticationOutcomeUnknown);
        };
        let request = RuntimeLogoutRequest {
            operation_id: proof.operation_id.clone(),
            refresh_token: proof.refresh_proof.clone(),
        };
        // Initiate both immediately; physical stop failure must not suppress
        // revocation, and a slow remote server must not delay the stop attempt.
        let (stop, response) = tokio::join!(
            tokio::time::timeout(REQUEST_TIMEOUT, self.stop.stop_local()),
            tokio::time::timeout(REQUEST_TIMEOUT, async {
                self.stop.prepare_revocation(epoch).await?;
                self.api
                    .logout_runtime(&request)
                    .await
                    .map_err(BrokerError::from)
            })
        );
        let stop = stop
            .map_err(|_| BrokerError::Timeout)
            .and_then(|result| result);
        let response = response.map_err(|_| BrokerError::Timeout)??;
        if !matches!(
            response.code.as_str(),
            "already_inactive" | "session_revoked_cleanup_accepted"
        ) {
            return Err(BrokerError::RecoveryRequired);
        }
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        if auth.auth_epoch == epoch && auth.logout_state == LogoutState::LoggedOut {
            // Another caller completed this same pending revocation. Keep its
            // durable result; this caller still reports its own stop outcome.
            return stop;
        }
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
        auth.completed_runtime_logout =
            proof.source.clone().map(|source| CompletedRuntimeLogoutV1 {
                operation_id: proof.operation_id.clone(),
                source,
                code: response.code.clone(),
                cleanup_reconcile_operation_id: response.cleanup_reconcile_operation_id.clone(),
            });
        let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
        meta.pending_logout = None;
        meta.completed_resume = None;
        meta.pending_login_account = None;
        self.store.save(&auth)?;
        stop
    }

    pub async fn completed_runtime_logout(
        &self,
    ) -> Result<Option<CompletedRuntimeLogoutV1>, BrokerError> {
        let _state = self.state.lock().await;
        Ok(self.load()?.completed_runtime_logout)
    }

    pub(crate) async fn stop_runtime_logout_cleanup(
        &self,
        receipt: &CompletedRuntimeLogoutV1,
    ) -> Result<(), BrokerError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            // Called under actual runtime writer quiescence. Serializing with
            // issuance also prevents a password login during this stop retry.
            let _issuance = self.issuance.lock().await;
            {
                let _state = self.state.lock().await;
                let auth = self.load()?;
                if auth.completed_runtime_logout.as_ref() != Some(receipt)
                    || auth.logout_state != LogoutState::LoggedOut
                {
                    return Err(BrokerError::Cancelled);
                }
            }
            self.stop.stop_local().await
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    pub(crate) async fn logout_covers_transition(
        &self,
        receipt: &CompletedRuntimeLogoutV1,
        operation_id: &str,
        source_scope_fingerprint: &str,
        source_device_id: Option<&str>,
    ) -> Result<bool, BrokerError> {
        let _state = self.state.lock().await;
        let auth = self.load()?;
        if auth.completed_runtime_logout.as_ref() != Some(receipt) {
            return Err(BrokerError::Cancelled);
        }
        if source_device_id != Some(receipt.source.device_id.as_str()) {
            return Ok(false);
        }
        if source_scope_fingerprint == receipt.source.scope_fingerprint {
            return Ok(true);
        }
        // Resume/supersede may have advanced identity, but only this exact
        // protected family/epoch can discharge the original cleanup snapshot.
        Ok(auth.broker.as_ref().is_some_and(|meta| {
            meta.transition_authorities.iter().any(|authority| {
                authority.reconcile_operation_id == operation_id
                    && authority.source_scope_fingerprint == source_scope_fingerprint
                    && authority.source_device_id == receipt.source.device_id
                    && authority.source_family == receipt.source.family
                    && authority.source_auth_epoch == receipt.source.auth_epoch
            })
        }))
    }

    pub async fn finish_runtime_logout_cleanup(
        &self,
        receipt: &CompletedRuntimeLogoutV1,
    ) -> Result<(), BrokerError> {
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        match auth.completed_runtime_logout.as_ref() {
            None => return Ok(()),
            Some(current) if current == receipt => {}
            Some(_) => return Err(BrokerError::Cancelled),
        }
        if auth
            .pending_runtime_supersede
            .as_ref()
            .is_some_and(|ticket| {
                ticket.source.family == receipt.source.family
                    && ticket.source.device_id == receipt.source.device_id
            })
        {
            auth.pending_runtime_supersede = None;
        }
        auth.completed_runtime_logout = None;
        self.store.save(&auth)?;
        Ok(())
    }

    /// Owner-only: issue provenance before invoking a platform recovery. The
    /// ticket must never be reconstructed from caller-provided identity fields.
    pub async fn begin_background_recovery(&self) -> Result<RecoveryTicketV1, BrokerError> {
        let _issuance = self.issuance.lock().await;
        let _state = self.state.lock().await;
        let mut auth = self.load()?;
        self.begin_native_locked(&mut auth)
    }

    fn begin_native_locked(&self, auth: &mut AuthStoreV1) -> Result<RecoveryTicketV1, BrokerError> {
        Self::active(auth)?;
        Self::ensure_transition_issuance_allowed(auth, None)?;
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
            device_id: Some(
                meta.confirmed_device_id
                    .clone()
                    .ok_or(BrokerError::RecoveryRequired)?,
            ),
        };
        meta.pending_recovery = Some(ticket.clone());
        self.store.save(auth)?;
        Ok(ticket)
    }

    /// One owner budget includes issuance wait and native dispatch. The native
    /// request carries the same deadline so a late executor cannot persist writes.
    pub(crate) async fn native_auth<C, F, Fut>(
        &self,
        check_admission: C,
        dispatch: F,
        recover: bool,
    ) -> Result<AccessSnapshot, BrokerError>
    where
        C: FnOnce(&AccessSnapshot) -> Result<(), BrokerError>,
        F: FnOnce(NativeAuthRequest) -> Fut,
        Fut: std::future::Future<Output = Result<Option<TokenResponse>, NativeAuthFailure>>,
    {
        self.native_auth_until(
            check_admission,
            dispatch,
            recover,
            tokio::time::Instant::now() + REQUEST_TIMEOUT,
        )
        .await
    }

    pub(crate) async fn native_auth_until<C, F, Fut>(
        &self,
        check_admission: C,
        dispatch: F,
        recover: bool,
        deadline: tokio::time::Instant,
    ) -> Result<AccessSnapshot, BrokerError>
    where
        C: FnOnce(&AccessSnapshot) -> Result<(), BrokerError>,
        F: FnOnce(NativeAuthRequest) -> Fut,
        Fut: std::future::Future<Output = Result<Option<TokenResponse>, NativeAuthFailure>>,
    {
        Self::check_deadline(Some(deadline))?;
        let expires_at_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| BrokerError::RecoveryRequired)?
            .as_millis()
            .saturating_add(
                deadline
                    .saturating_duration_since(tokio::time::Instant::now())
                    .as_millis(),
            );
        tokio::time::timeout_at(deadline, async {
            let fence = self.capture_login_fence().await?;
            let _issuance = self.issuance.lock().await;
            let request = {
                let _state = self.state.lock().await;
                Self::check_deadline(Some(deadline))?;
                let mut auth = self.load()?;
                if auth.auth_epoch != fence.epoch
                    || auth.broker.as_ref().map(|m| m.family.as_str())
                        != Some(fence.family.as_str())
                {
                    return Err(BrokerError::Cancelled);
                }
                let access = Self::snapshot(&auth)?;
                check_admission(&access)?;
                if !recover && Self::observed_state(&auth)? != BrokerAuthState::Active {
                    return Err(BrokerError::RecoveryRequired);
                }
                let ticket = self.begin_native_locked(&mut auth)?;
                NativeAuthRequest {
                    ticket,
                    access,
                    install_secret: auth.install_secret,
                    expires_at_unix_ms: u64::try_from(expires_at_unix_ms)
                        .map_err(|_| BrokerError::RecoveryRequired)?,
                }
            };
            let ticket = request.ticket.clone();
            let response = dispatch(request).await;
            Self::check_deadline(Some(deadline))?;
            match response {
                Ok(Some(response)) if recover => {
                    self.accept_background_recovery_inner(&ticket, response, Some(deadline))
                        .await
                }
                other => {
                    let _state = self.state.lock().await;
                    Self::check_deadline(Some(deadline))?;
                    let mut auth = self.load()?;
                    Self::active(&auth)?;
                    let meta = auth.broker.as_mut().ok_or(BrokerError::RecoveryRequired)?;
                    if meta.pending_recovery.as_ref() != Some(&ticket)
                        || auth.auth_epoch != ticket.auth_epoch
                        || meta.family != ticket.family
                        || meta.next_attempt != ticket.attempt
                    {
                        return Err(BrokerError::Cancelled);
                    }
                    if !recover
                        || matches!(
                            other,
                            Err(NativeAuthFailure::NotIssued | NativeAuthFailure::AccessUnavailable)
                        )
                    {
                        meta.pending_recovery = None;
                        self.store.save(&auth)?;
                    }
                    if matches!(other, Err(NativeAuthFailure::AccessUnavailable)) {
                        Err(BrokerError::AccessUnavailable)
                    } else if !recover && matches!(other, Ok(None)) {
                        Self::snapshot(&auth)
                    } else {
                        Err(BrokerError::RecoveryRequired)
                    }
                }
            }
        })
        .await
        .map_err(|_| BrokerError::Timeout)?
    }

    /// Owner callback ingress, not runtime IPC. No network request is made with
    /// returned refresh: validate protected provenance *before* accepting data.
    pub async fn accept_background_recovery(
        &self,
        ticket: &RecoveryTicketV1,
        response: TokenResponse,
    ) -> Result<AccessSnapshot, BrokerError> {
        self.accept_background_recovery_inner(ticket, response, None)
            .await
    }

    fn check_deadline(deadline: Option<tokio::time::Instant>) -> Result<(), BrokerError> {
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            Err(BrokerError::Timeout)
        } else {
            Ok(())
        }
    }

    async fn accept_background_recovery_inner(
        &self,
        ticket: &RecoveryTicketV1,
        response: TokenResponse,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<AccessSnapshot, BrokerError> {
        let _state = self.state.lock().await;
        Self::check_deadline(deadline)?;
        let mut auth = self.load()?;
        Self::active(&auth)?;
        let meta = auth.broker.as_ref().ok_or(BrokerError::RecoveryRequired)?;
        if meta.pending_recovery.as_ref() != Some(ticket)
            || meta.next_attempt != ticket.attempt
            || meta.family != ticket.family
            || auth.auth_epoch != ticket.auth_epoch
            || auth.confirmed_identity.as_ref() != Some(&ticket.identity)
            || ticket.device_id.is_none()
            || meta.confirmed_device_id != ticket.device_id
        {
            return Err(BrokerError::Cancelled);
        }
        if response.device.confirmed_identity()? != ticket.identity
            || Some(response.device.id.as_str()) != ticket.device_id.as_deref()
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
