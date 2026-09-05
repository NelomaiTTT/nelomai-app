//! Container/broker-owned credentials; these types are not runtime IPC DTOs.
use crate::{ProtectedRecordStore, StorageError, StoredAuth, SystemSecretStore};
use nelomai_contracts::RuntimeIdentity;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, path::PathBuf};

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
        Ok(())
    }
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
