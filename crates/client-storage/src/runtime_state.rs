//! Exact-version operational state. Paths are logical names; secret-bearing
//! state is held by a protected record backend, not a plaintext pointer file.
use crate::{
    auth::{decode_record, encode_record},
    ProtectedRecordStore, StorageError, StoredAuth, StoredCompatibility, StoredConnection,
    StoredPendingCompensationStop, StoredPendingStalledStop, StoredPendingStart,
    StoredSplitTunnelState, SystemSecretStore,
};
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePaths {
    pub preferences: PathBuf,
    pub operational_state: PathBuf,
    slot: RuntimeSlot,
    version: String,
    namespace: String,
}
impl RuntimePaths {
    pub fn new(
        root: impl AsRef<Path>,
        slot: RuntimeSlot,
        runtime_version: &str,
    ) -> Result<Self, StorageError> {
        let identity = RuntimeIdentity {
            slot,
            runtime_version: runtime_version.into(),
            runtime_contract_version: 1,
            container_version: runtime_version.into(),
            session_generation: None,
        };
        identity
            .validate()
            .map_err(|_| StorageError::RecoveryRequired("invalid runtime path version"))?;
        if runtime_version.ends_with('.') {
            return Err(StorageError::RecoveryRequired(
                "nonportable runtime path version",
            ));
        }
        let slot_name = match slot {
            RuntimeSlot::Latest => "latest",
            RuntimeSlot::Stable => "stable",
        };
        let namespace = format!("runtime/{slot_name}/state/{runtime_version}/state-v1.json");
        let preferences = match slot {
            RuntimeSlot::Latest => root.as_ref().join("runtime/latest/preferences-v1.json"),
            RuntimeSlot::Stable => root.as_ref().join(format!(
                "runtime/stable/{runtime_version}/preferences-v1.json"
            )),
        };
        Ok(Self {
            preferences,
            operational_state: root.as_ref().join(&namespace),
            slot,
            version: runtime_version.into(),
            namespace,
        })
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn slot(&self) -> RuntimeSlot {
        self.slot
    }
    pub fn runtime_version(&self) -> &str {
        &self.version
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStateV1 {
    pub schema_version: u32,
    pub slot: RuntimeSlot,
    pub runtime_version: String,
    /// Imported legacy state is cleanup input, never an adoptable tunnel.
    pub cleanup_only: bool,
    pub saved_connection: Option<StoredConnection>,
    pub pinned_connection: Option<StoredConnection>,
    pub pending_start: Option<StoredPendingStart>,
    pub pending_stalled_stop: Option<StoredPendingStalledStop>,
    pub pending_compensation_stop: Option<StoredPendingCompensationStop>,
    pub compatibility: Option<StoredCompatibility>,
    pub applied_split_tunnel: StoredSplitTunnelState,
}
impl fmt::Debug for RuntimeStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeStateV1")
            .field("slot", &self.slot)
            .field("runtime_version", &self.runtime_version)
            .field("cleanup_only", &self.cleanup_only)
            .field("operational_payload", &"<redacted>")
            .finish()
    }
}
impl RuntimeStateV1 {
    pub fn import_legacy(
        auth: &StoredAuth,
        split: StoredSplitTunnelState,
        paths: &RuntimePaths,
    ) -> Self {
        Self {
            schema_version: 1,
            slot: paths.slot,
            runtime_version: paths.version.clone(),
            cleanup_only: true,
            saved_connection: auth.saved_connection.clone(),
            pinned_connection: auth.pinned_connection.clone(),
            pending_start: auth.pending_start.clone(),
            pending_stalled_stop: auth.pending_stalled_stop.clone(),
            pending_compensation_stop: auth.pending_compensation_stop.clone(),
            compatibility: auth.compatibility.clone(),
            applied_split_tunnel: split,
        }
    }
    pub fn start_or_recovery_allowed(&self) -> bool {
        !self.cleanup_only
    }
    /// Called by the broker only after server/local cleanup acknowledgement.
    pub fn complete_legacy_cleanup(&mut self) {
        self.saved_connection = None;
        self.pinned_connection = None;
        self.pending_start = None;
        self.pending_stalled_stop = None;
        self.pending_compensation_stop = None;
        self.compatibility = None;
        self.applied_split_tunnel = StoredSplitTunnelState::default();
        self.cleanup_only = false;
    }
    pub(crate) fn project(&self, auth: &crate::AuthStoreV1) -> StoredAuth {
        StoredAuth {
            install_secret: auth.install_secret.clone(),
            access_token: auth.access_token.clone(),
            refresh_token: auth.refresh_token.clone(),
            saved_connection: self.saved_connection.clone(),
            pinned_connection: self.pinned_connection.clone(),
            pending_start: self.pending_start.clone(),
            pending_stalled_stop: self.pending_stalled_stop.clone(),
            pending_compensation_stop: self.pending_compensation_stop.clone(),
            compatibility: self.compatibility.clone(),
        }
    }
    pub(crate) fn save_projection(&mut self, value: &StoredAuth) {
        self.saved_connection = value.saved_connection.clone();
        self.pinned_connection = value.pinned_connection.clone();
        self.pending_start = value.pending_start.clone();
        self.pending_stalled_stop = value.pending_stalled_stop.clone();
        self.pending_compensation_stop = value.pending_compensation_stop.clone();
        self.compatibility = value.compatibility.clone();
    }
}
pub trait RuntimeStateStore: Send + Sync {
    fn paths(&self) -> &RuntimePaths;
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError>;
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError>;
}
pub struct ProtectedRuntimeStore<R> {
    record: R,
    paths: RuntimePaths,
}
impl<R: ProtectedRecordStore> ProtectedRuntimeStore<R> {
    pub fn new(record: R, paths: RuntimePaths) -> Self {
        Self { record, paths }
    }
    fn validate(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        if value.schema_version != 1
            || value.slot != self.paths.slot
            || value.runtime_version != self.paths.version
        {
            Err(StorageError::RecoveryRequired(
                "runtime schema or exact version mismatch",
            ))
        } else {
            Ok(())
        }
    }
}
impl ProtectedRuntimeStore<SystemSecretStore> {
    pub fn system(
        legacy_account: &str,
        linux_fallback_dir: Option<PathBuf>,
        paths: RuntimePaths,
    ) -> Self {
        let account = format!("{legacy_account}:{}", paths.namespace());
        Self::new(SystemSecretStore::new(account, linux_fallback_dir), paths)
    }
}
impl<R: ProtectedRecordStore> RuntimeStateStore for ProtectedRuntimeStore<R> {
    fn paths(&self) -> &RuntimePaths {
        &self.paths
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        self.record
            .load_record()?
            .map(|bytes| {
                let value = decode_record(&bytes, self.paths.namespace())?;
                self.validate(&value)?;
                Ok(value)
            })
            .transpose()
    }
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        self.validate(value)?;
        self.record
            .save_record(&encode_record(value, self.paths.namespace())?)
    }
}
