//! Container/broker-owned credentials; these types are not runtime IPC DTOs.
use crate::{ProtectedRecordStore, StorageError, StoredAuth, SystemSecretStore};
use nelomai_contracts::RuntimeIdentity;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, path::PathBuf};
use uuid::Uuid;

pub const MAX_TRANSITION_AUTHORITIES: usize = 16;
pub const MAX_AUTH_RECORD_WITH_TRANSITION_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogoutState {
    Active,
    Pending,
    LoggedOut,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeResultV1 {
    pub identity: RuntimeIdentity,
    pub access_token: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingResumeV1 {
    pub operation_id: String,
    pub fingerprint: String,
    pub target_identity: RuntimeIdentity,
    pub result: Option<ResumeResultV1>,
}

/// Protected broker journal. The local lineage is a cancellation/provenance
/// identifier, not a server auth_family_id and never a substitute for identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerMetadataV1 {
    pub family: String,
    pub next_attempt: u64,
    pub pending_request: Option<BrokerRequestV1>,
    pub completed_resume: Option<CompletedResumeV1>,
    pub pending_logout: Option<PendingLogoutV1>,
    #[serde(default)]
    pub pending_recovery: Option<RecoveryTicketV1>,
    #[serde(default)]
    pub cancelled_login: Option<BrokerRequestV1>,
    #[serde(default)]
    pub authentication_outcome_unknown: bool,
    /// Retained only for an unresolved password attempt. Explicit recovery must
    /// use the same account/install pair so server per-device revocation applies.
    #[serde(default)]
    pub pending_login_account: Option<String>,
    /// Server device UUID, never derived from the spelling of a login name.
    #[serde(default)]
    pub confirmed_device_id: Option<String>,
    /// Nonsecret local delivery cleanup, independent of server logout ACK.
    #[serde(default)]
    pub pending_push_cleanup_epoch: Option<u64>,
    #[serde(default)]
    pub transition_authorities: Vec<TransitionAuthorityV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionDispatchStateV1 {
    Captured,
    DispatchIntent,
    OutcomeUnknown,
    InvalidAccessRejected,
    ResponseKnown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionReconcileReceiptV1 {
    pub state: String,
    pub operation_id: String,
    pub retired_lease_ids: Vec<String>,
    pub retired_session_ids: Vec<String>,
    pub retired_operation_ids: Vec<String>,
    pub retry_after_seconds: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionResumeEvidenceV1 {
    pub operation_id: String,
    pub reconcile_operation_id: String,
    pub decision: String,
    pub target_identity: RuntimeIdentity,
    pub identity: RuntimeIdentity,
    pub access_token: String,
}
impl fmt::Debug for TransitionResumeEvidenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitionResumeEvidenceV1")
            .field("operation_id", &self.operation_id)
            .field("reconcile_operation_id", &self.reconcile_operation_id)
            .field("decision", &self.decision)
            .field("target_identity", &self.target_identity)
            .field("identity", &self.identity)
            .field("access_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionAuthorityV1 {
    pub schema_version: u32,
    pub reconcile_operation_id: String,
    pub request_fingerprint: String,
    pub source_auth_epoch: u64,
    pub source_family: String,
    pub source_identity: Option<RuntimeIdentity>,
    pub source_device_id: String,
    pub source_scope_fingerprint: String,
    pub expected_session_generation: Option<u64>,
    pub target_identity: RuntimeIdentity,
    pub cleanup_contract_version: u32,
    pub cleanup_access_proof: String,
    pub resume_refresh_proof: String,
    pub dispatch_state: TransitionDispatchStateV1,
    pub reconcile_receipt: Option<TransitionReconcileReceiptV1>,
    pub resume_ticket: Option<BrokerRequestV1>,
    pub resume_evidence: Option<TransitionResumeEvidenceV1>,
}
impl fmt::Debug for TransitionAuthorityV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransitionAuthorityV1")
            .field("reconcile_operation_id", &self.reconcile_operation_id)
            .field("request_fingerprint", &self.request_fingerprint)
            .field("source_auth_epoch", &self.source_auth_epoch)
            .field("source_family", &self.source_family)
            .field("source_identity", &self.source_identity)
            .field("source_device_id", &self.source_device_id)
            .field("source_scope_fingerprint", &self.source_scope_fingerprint)
            .field("target_identity", &self.target_identity)
            .field("dispatch_state", &self.dispatch_state)
            .field("reconcile_receipt", &self.reconcile_receipt)
            .field("resume_ticket", &self.resume_ticket)
            .field("resume_evidence", &self.resume_evidence)
            .field("credentials", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTicketV1 {
    pub operation_id: String,
    pub auth_epoch: u64,
    pub attempt: u64,
    pub family: String,
    pub identity: RuntimeIdentity,
    /// Old staged tickets remain readable for cleanup, never accepted without
    /// an owner-confirmed device ID.
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerRequestKind {
    Refresh,
    Resume,
    Login,
    LegacyBootstrap,
    LegacyRefresh,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredResumeArgumentsV1 {
    pub reconcile_operation_id: String,
    pub decision: String,
    pub target: RuntimeIdentity,
    pub expected_session_generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequestV1 {
    pub kind: BrokerRequestKind,
    pub operation_id: String,
    pub attempt: u64,
    pub auth_epoch: u64,
    pub source_identity: Option<RuntimeIdentity>,
    #[serde(default)]
    pub source_device_id: Option<String>,
    #[serde(default)]
    pub prior_login_outcome_unknown: bool,
    pub resume: Option<StoredResumeArgumentsV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedResumeV1 {
    pub request: BrokerRequestV1,
    pub identity: RuntimeIdentity,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingLogoutV1 {
    pub operation_id: String,
    pub refresh_proof: String,
}
impl fmt::Debug for PendingLogoutV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingLogoutV1")
            .field("operation_id", &self.operation_id)
            .field("refresh_proof", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthStoreV1 {
    pub schema_version: u32,
    pub install_secret: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    /// Server-issued only; a local migration never enrolls the device.
    pub session_generation: Option<u64>,
    /// Local cancellation fence. Never substitute this for server generation.
    pub auth_epoch: u64,
    pub logout_state: LogoutState,
    #[serde(default)]
    pub confirmed_identity: Option<RuntimeIdentity>,
    #[serde(default)]
    pub pending_resume: Option<PendingResumeV1>,
    #[serde(default)]
    pub broker: Option<BrokerMetadataV1>,
}

impl fmt::Debug for ResumeResultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResumeResultV1")
            .field("identity", &self.identity)
            .field("access_token", &"<redacted>")
            .finish()
    }
}
impl fmt::Debug for PendingResumeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingResumeV1")
            .field("operation_id", &self.operation_id)
            .field("target_identity", &self.target_identity)
            .field("result", &self.result)
            .finish()
    }
}
impl fmt::Debug for AuthStoreV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthStoreV1")
            .field("credentials", &"<redacted>")
            .field("session_generation", &self.session_generation)
            .field("auth_epoch", &self.auth_epoch)
            .field("logout_state", &self.logout_state)
            .field("confirmed_identity", &self.confirmed_identity)
            .field("pending_resume", &self.pending_resume)
            .finish()
    }
}

impl AuthStoreV1 {
    pub fn validate_transition_write_budget(&self) -> Result<(), StorageError> {
        if encode_record(self, "auth-v1")?.len() > MAX_AUTH_RECORD_WITH_TRANSITION_BYTES {
            return Err(StorageError::RecoveryRequired(
                "protected transition authority budget exceeded",
            ));
        }
        Ok(())
    }

    pub fn from_legacy(legacy: &StoredAuth) -> Self {
        Self {
            schema_version: 1,
            install_secret: legacy.install_secret.clone(),
            access_token: legacy.access_token.clone(),
            refresh_token: legacy.refresh_token.clone(),
            session_generation: None,
            auth_epoch: 0,
            logout_state: LogoutState::Active,
            confirmed_identity: None,
            pending_resume: None,
            broker: None,
        }
    }
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.schema_version != 1
            || self.install_secret.is_empty()
            || self
                .session_generation
                .is_some_and(|g| g == 0 || g > i64::MAX as u64)
        {
            return Err(StorageError::RecoveryRequired(
                "invalid auth schema or identity",
            ));
        }
        if let Some(identity) = &self.confirmed_identity {
            identity
                .validate()
                .map_err(|_| StorageError::RecoveryRequired("invalid confirmed identity"))?;
            if identity.session_generation.is_none()
                || identity.session_generation != self.session_generation
            {
                return Err(StorageError::RecoveryRequired(
                    "confirmed generation mismatch",
                ));
            }
        }
        if let Some(pending) = &self.pending_resume {
            pending
                .target_identity
                .validate()
                .map_err(|_| StorageError::RecoveryRequired("invalid resume target"))?;
            if pending.operation_id.is_empty() || !valid_digest(&pending.fingerprint) {
                return Err(StorageError::RecoveryRequired("invalid pending resume"));
            }
            if let Some(result) = &pending.result {
                result
                    .identity
                    .validate()
                    .map_err(|_| StorageError::RecoveryRequired("invalid resume result"))?;
                if result.identity.session_generation.is_none() || result.access_token.is_empty() {
                    return Err(StorageError::RecoveryRequired("incomplete resume result"));
                }
            }
        }
        if let Some(meta) = &self.broker {
            if meta.family.is_empty() || meta.family.len() > 128 {
                return Err(StorageError::RecoveryRequired("invalid broker lineage"));
            }
            if meta
                .pending_login_account
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 64)
            {
                return Err(StorageError::RecoveryRequired(
                    "invalid pending login account",
                ));
            }
            if meta
                .pending_push_cleanup_epoch
                .is_some_and(|epoch| epoch > self.auth_epoch)
            {
                return Err(StorageError::RecoveryRequired("invalid push cleanup epoch"));
            }
            let validate_request = |request: &BrokerRequestV1| -> Result<(), StorageError> {
                if request.operation_id.is_empty()
                    || request.operation_id.len() > 128
                    || request.attempt == 0
                    || request.attempt > meta.next_attempt
                    || request.auth_epoch > self.auth_epoch
                {
                    return Err(StorageError::RecoveryRequired(
                        "invalid broker request ticket",
                    ));
                }
                if let Some(identity) = &request.source_identity {
                    identity.validate().map_err(|_| {
                        StorageError::RecoveryRequired("invalid broker source identity")
                    })?;
                }
                if let Some(resume) = &request.resume {
                    resume.target.validate().map_err(|_| {
                        StorageError::RecoveryRequired("invalid broker resume target")
                    })?;
                    if resume.target.session_generation.is_some()
                        || resume.reconcile_operation_id.is_empty()
                        || !matches!(resume.decision.as_str(), "apply" | "cancel")
                        || resume
                            .expected_session_generation
                            .is_some_and(|g| g == 0 || g > i64::MAX as u64)
                    {
                        return Err(StorageError::RecoveryRequired(
                            "invalid broker resume arguments",
                        ));
                    }
                }
                if (request.kind == BrokerRequestKind::Resume) != request.resume.is_some() {
                    return Err(StorageError::RecoveryRequired(
                        "invalid broker request kind",
                    ));
                }
                if matches!(
                    request.kind,
                    BrokerRequestKind::LegacyBootstrap | BrokerRequestKind::LegacyRefresh
                ) && (!canonical_uuid(&request.operation_id)
                    || request.auth_epoch != self.auth_epoch
                    || request.source_identity.is_some()
                    || request.source_device_id != meta.confirmed_device_id
                    || request.prior_login_outcome_unknown)
                {
                    return Err(StorageError::RecoveryRequired(
                        "invalid legacy transition ticket",
                    ));
                }
                Ok(())
            };
            if let Some(request) = &meta.pending_request {
                validate_request(request)?;
            }
            if let Some(request) = &meta.cancelled_login {
                validate_request(request)?;
                if request.kind != BrokerRequestKind::Login {
                    return Err(StorageError::RecoveryRequired("invalid cancelled login"));
                }
            }
            if let Some(done) = &meta.completed_resume {
                validate_request(&done.request)?;
                done.identity.validate().map_err(|_| {
                    StorageError::RecoveryRequired("invalid completed resume identity")
                })?;
                if done.request.kind != BrokerRequestKind::Resume
                    || done.identity.session_generation.is_none()
                {
                    return Err(StorageError::RecoveryRequired("invalid completed resume"));
                }
            }
            if let Some(logout) = &meta.pending_logout {
                if logout.operation_id.is_empty() || logout.refresh_proof.is_empty() {
                    return Err(StorageError::RecoveryRequired("invalid logout proof"));
                }
            }
            if let Some(recovery) = &meta.pending_recovery {
                recovery
                    .identity
                    .validate()
                    .map_err(|_| StorageError::RecoveryRequired("invalid recovery identity"))?;
                if recovery.operation_id.is_empty()
                    || recovery.family.is_empty()
                    || recovery.identity.session_generation.is_none()
                    || recovery.attempt == 0
                    || recovery.attempt > meta.next_attempt
                    || recovery.auth_epoch > self.auth_epoch
                {
                    return Err(StorageError::RecoveryRequired("invalid recovery ticket"));
                }
            }
            if meta.transition_authorities.len() > MAX_TRANSITION_AUTHORITIES
                || meta
                    .transition_authorities
                    .iter()
                    .map(|authority| authority.reconcile_operation_id.as_str())
                    .collect::<HashSet<_>>()
                    .len()
                    != meta.transition_authorities.len()
            {
                return Err(StorageError::RecoveryRequired(
                    "invalid transition authority collection",
                ));
            }
            for authority in &meta.transition_authorities {
                validate_transition_authority(authority, &validate_request)?;
            }
        }
        Ok(())
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}

fn valid_ids(values: &[String]) -> bool {
    values.len() <= 1024
        && values.iter().all(|value| {
            !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
        })
        && values.iter().collect::<HashSet<_>>().len() == values.len()
}

fn validate_transition_authority(
    authority: &TransitionAuthorityV1,
    validate_request: &impl Fn(&BrokerRequestV1) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let source_valid = match &authority.source_identity {
        Some(identity) => {
            identity.validate().is_ok()
                && identity.session_generation.is_some()
                && identity.session_generation == authority.expected_session_generation
        }
        None => authority.expected_session_generation.is_none(),
    };
    if authority.schema_version != 1
        || !canonical_uuid(&authority.reconcile_operation_id)
        || !valid_digest(&authority.request_fingerprint)
        || !valid_digest(&authority.source_scope_fingerprint)
        || authority.source_family.is_empty()
        || authority.source_family.len() > 128
        || !source_valid
        || authority.source_device_id.is_empty()
        || authority.source_device_id.len() > 256
        || authority.target_identity.validate().is_err()
        || authority.target_identity.session_generation.is_some()
        || authority.cleanup_contract_version != 1
        || authority.cleanup_access_proof.is_empty()
        || authority.cleanup_access_proof.len() > 256
        || authority.resume_refresh_proof.is_empty()
        || authority.resume_refresh_proof.len() > 256
        || (authority.dispatch_state == TransitionDispatchStateV1::ResponseKnown)
            != authority.reconcile_receipt.is_some()
    {
        return Err(StorageError::RecoveryRequired(
            "invalid transition authority",
        ));
    }
    if let Some(receipt) = &authority.reconcile_receipt {
        if receipt.operation_id != authority.reconcile_operation_id
            || !matches!(receipt.state.as_str(), "clean" | "retry")
            || !valid_ids(&receipt.retired_lease_ids)
            || !valid_ids(&receipt.retired_session_ids)
            || !valid_ids(&receipt.retired_operation_ids)
            || receipt
                .retry_after_seconds
                .is_some_and(|seconds| !(1..=30).contains(&seconds))
        {
            return Err(StorageError::RecoveryRequired(
                "invalid transition reconcile receipt",
            ));
        }
    }
    if let Some(ticket) = &authority.resume_ticket {
        validate_request(ticket)?;
        let resume = ticket
            .resume
            .as_ref()
            .ok_or(StorageError::RecoveryRequired(
                "invalid transition resume ticket",
            ))?;
        if ticket.kind != BrokerRequestKind::Resume
            || ticket.auth_epoch != authority.source_auth_epoch
            || ticket.source_identity != authority.source_identity
            || ticket.source_device_id.as_deref() != Some(&authority.source_device_id)
            || resume.reconcile_operation_id != authority.reconcile_operation_id
            || resume.target != authority.target_identity
            || resume.expected_session_generation != authority.expected_session_generation
        {
            return Err(StorageError::RecoveryRequired(
                "invalid transition resume ticket",
            ));
        }
    }
    if let Some(evidence) = &authority.resume_evidence {
        let ticket = authority
            .resume_ticket
            .as_ref()
            .ok_or(StorageError::RecoveryRequired(
                "orphan transition resume evidence",
            ))?;
        let resume = ticket
            .resume
            .as_ref()
            .ok_or(StorageError::RecoveryRequired(
                "invalid transition resume evidence",
            ))?;
        if evidence.operation_id != ticket.operation_id
            || evidence.reconcile_operation_id != authority.reconcile_operation_id
            || evidence.decision != resume.decision
            || evidence.target_identity != authority.target_identity
            || evidence.identity.validate().is_err()
            || evidence.identity.session_generation
                != authority
                    .expected_session_generation
                    .unwrap_or(0)
                    .checked_add(1)
            || (RuntimeIdentity {
                session_generation: None,
                ..evidence.identity.clone()
            }) != authority.target_identity
            || evidence.access_token.is_empty()
            || evidence.access_token.len() > 256
        {
            return Err(StorageError::RecoveryRequired(
                "invalid transition resume evidence",
            ));
        }
    }
    Ok(())
}

pub trait AuthStore: Send + Sync {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError>;
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError>;
}

pub struct ProtectedAuthStore<R> {
    record: R,
}
impl<R: ProtectedRecordStore> ProtectedAuthStore<R> {
    /// The supplied backend must be a dedicated auth-v1 account, not legacy.
    pub fn new(record: R) -> Self {
        Self { record }
    }
}
impl ProtectedAuthStore<SystemSecretStore> {
    pub fn system(legacy_account: &str, linux_fallback_dir: Option<PathBuf>) -> Self {
        Self::new(SystemSecretStore::new(
            format!("{legacy_account}:auth-v1"),
            linux_fallback_dir,
        ))
    }
}
impl<R: ProtectedRecordStore> AuthStore for ProtectedAuthStore<R> {
    fn load(&self) -> Result<Option<AuthStoreV1>, StorageError> {
        self.record
            .load_record()?
            .map(|bytes| {
                let value: AuthStoreV1 = decode_record(&bytes, "auth-v1")?;
                value.validate()?;
                Ok(value)
            })
            .transpose()
    }
    fn save(&self, value: &AuthStoreV1) -> Result<(), StorageError> {
        value.validate()?;
        self.record.save_record(&encode_record(value, "auth-v1")?)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    namespace: String,
    checksum: String,
    payload: Value,
}

pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String, StorageError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical(&serde_json::to_value(value)?))
    ))
}
pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn encode_record<T: Serialize>(
    value: &T,
    namespace: &str,
) -> Result<Vec<u8>, StorageError> {
    let payload = serde_json::to_value(value)?;
    Ok(canonical(&serde_json::to_value(Envelope {
        schema_version: 1,
        namespace: namespace.into(),
        checksum: digest(&payload)?,
        payload,
    })?))
}
pub(crate) fn decode_record<T: DeserializeOwned>(
    bytes: &[u8],
    namespace: &str,
) -> Result<T, StorageError> {
    let record: Envelope = serde_json::from_slice(bytes)
        .map_err(|_| StorageError::RecoveryRequired("invalid protected record"))?;
    if record.schema_version != 1
        || record.namespace != namespace
        || !valid_digest(&record.checksum)
        || record.checksum != digest(&record.payload)?
    {
        return Err(StorageError::RecoveryRequired(
            "record schema, namespace or checksum mismatch",
        ));
    }
    serde_json::from_value(record.payload)
        .map_err(|_| StorageError::RecoveryRequired("invalid protected payload"))
}
fn canonical(value: &Value) -> Vec<u8> {
    fn write(value: &Value, bytes: &mut Vec<u8>) {
        match value {
            Value::Object(fields) => {
                bytes.push(b'{');
                let mut sorted: Vec<_> = fields.iter().collect();
                sorted.sort_unstable_by(|a, b| a.0.cmp(b.0));
                for (i, (key, value)) in sorted.into_iter().enumerate() {
                    if i > 0 {
                        bytes.push(b',');
                    }
                    bytes.extend(serde_json::to_vec(key).expect("JSON key"));
                    bytes.push(b':');
                    write(value, bytes);
                }
                bytes.push(b'}');
            }
            Value::Array(items) => {
                bytes.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        bytes.push(b',');
                    }
                    write(item, bytes);
                }
                bytes.push(b']');
            }
            _ => bytes.extend(serde_json::to_vec(value).expect("JSON scalar")),
        }
    }
    let mut bytes = Vec::new();
    write(value, &mut bytes);
    bytes
}
