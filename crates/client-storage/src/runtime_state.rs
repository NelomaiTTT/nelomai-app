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
    sync::{Arc, Mutex},
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

/// Nonsecret provenance issued by the auth owner, not a server family ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthScope {
    pub auth_epoch: u64,
    pub family: String,
    pub identity: RuntimeIdentity,
}
impl RuntimeAuthScope {
    pub fn validate(&self) -> Result<(), StorageError> {
        self.identity
            .validate()
            .map_err(|_| StorageError::RecoveryRequired("invalid runtime auth scope"))?;
        if self.identity.session_generation.is_none()
            || self.family.is_empty()
            || self.family.len() > 256
        {
            return Err(StorageError::RecoveryRequired("invalid runtime auth scope"));
        }
        Ok(())
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
    /// Absent scope is quarantine, never inferred from the currently logged-in user.
    #[serde(default)]
    pub auth_scope: Option<RuntimeAuthScope>,
    pub saved_connection: Option<StoredConnection>,
    pub pinned_connection: Option<StoredConnection>,
    pub pending_start: Option<StoredPendingStart>,
    pub pending_stalled_stop: Option<StoredPendingStalledStop>,
    pub pending_compensation_stop: Option<StoredPendingCompensationStop>,
    pub compatibility: Option<StoredCompatibility>,
    pub applied_split_tunnel: StoredSplitTunnelState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCleanupOperationV1 {
    pub operation_id: String,
    pub request_fingerprint: Option<String>,
    pub contract_version: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCleanupSnapshotV1 {
    pub slot: RuntimeSlot,
    pub runtime_version: String,
    pub auth_scope: Option<RuntimeAuthScope>,
    pub lease_ids: Vec<String>,
    pub operations: Vec<RuntimeCleanupOperationV1>,
    pub cleanup_only: bool,
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
    pub fn empty(paths: &RuntimePaths, cleanup_only: bool) -> Self {
        Self {
            schema_version: 1,
            slot: paths.slot,
            runtime_version: paths.version.clone(),
            cleanup_only,
            auth_scope: None,
            saved_connection: None,
            pinned_connection: None,
            pending_start: None,
            pending_stalled_stop: None,
            pending_compensation_stop: None,
            compatibility: None,
            applied_split_tunnel: StoredSplitTunnelState::default(),
        }
    }

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
            auth_scope: None,
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
    pub fn operationally_empty(&self) -> bool {
        self.saved_connection.is_none()
            && self.pinned_connection.is_none()
            && self.pending_start.is_none()
            && self.pending_stalled_stop.is_none()
            && self.pending_compensation_stop.is_none()
            && self.compatibility.is_none()
            && self.applied_split_tunnel == StoredSplitTunnelState::default()
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
        self.auth_scope = None;
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

fn cleanup_snapshot(state: &RuntimeStateV1) -> RuntimeCleanupSnapshotV1 {
    let mut lease_ids = Vec::new();
    for lease_id in state
        .saved_connection
        .as_ref()
        .map(|connection| connection.lease_id.as_str())
        .into_iter()
        .chain(
            state
                .pinned_connection
                .as_ref()
                .map(|connection| connection.lease_id.as_str()),
        )
        .chain(
            state
                .pending_stalled_stop
                .as_ref()
                .map(|pending| pending.lease_id.as_str()),
        )
        .chain(
            state
                .pending_compensation_stop
                .as_ref()
                .map(|pending| pending.lease_id.as_str()),
        )
    {
        if !lease_ids.iter().any(|existing| existing == lease_id) {
            lease_ids.push(lease_id.to_owned());
        }
    }
    let mut operations = Vec::new();
    let mut push =
        |operation_id: &str, request_fingerprint: Option<String>, contract_version: Option<u32>| {
            if !operations
                .iter()
                .any(|existing: &RuntimeCleanupOperationV1| existing.operation_id == operation_id)
            {
                operations.push(RuntimeCleanupOperationV1 {
                    operation_id: operation_id.to_owned(),
                    request_fingerprint,
                    contract_version,
                });
            }
        };
    if let Some(pending) = &state.pending_start {
        push(
            &pending.operation_id,
            pending.request_fingerprint.clone(),
            pending.recovery_contract_version,
        );
        if let Some(cancel_operation_id) = &pending.cancel_operation_id {
            push(cancel_operation_id, None, None);
        }
    }
    if let Some(pending) = &state.pending_stalled_stop {
        push(
            &pending.operation_id,
            Some(pending.request_fingerprint.clone()),
            Some(pending.contract_version),
        );
    }
    if let Some(pending) = &state.pending_compensation_stop {
        push(&pending.operation_id, None, None);
    }
    RuntimeCleanupSnapshotV1 {
        slot: state.slot,
        runtime_version: state.runtime_version.clone(),
        auth_scope: state.auth_scope.clone(),
        lease_ids,
        operations,
        cleanup_only: state.cleanup_only,
    }
}
pub trait RuntimeStateStore: Send + Sync {
    fn paths(&self) -> &RuntimePaths;
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError>;
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError>;
}

/// Sole live-process owner of one exact runtime record. Startup migration and
/// stopped-runtime coordination must relinquish all full-writer handles before
/// this owner is handed to a runtime. This mutex is not a cross-process lock:
/// the container must enforce single-process ownership separately.
pub struct RuntimeRecordOwner<S> {
    backend: S,
    gate: Mutex<()>,
}

impl<S: RuntimeStateStore> RuntimeRecordOwner<S> {
    pub fn new(backend: S) -> Arc<Self> {
        Arc::new(Self {
            backend,
            gate: Mutex::new(()),
        })
    }
    pub fn operational(self: &Arc<Self>) -> RuntimeOperationalStore<S> {
        RuntimeOperationalStore {
            owner: self.clone(),
        }
    }
    pub fn split(self: &Arc<Self>) -> RuntimeSplitTunnelStore<S> {
        RuntimeSplitTunnelStore {
            owner: self.clone(),
        }
    }
    pub fn check_scope(&self, scope: &RuntimeAuthScope) -> Result<(), StorageError> {
        scope.validate()?;
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let current = self.load_required()?;
        if current.cleanup_only || current.auth_scope.as_ref() != Some(scope) {
            return Err(StorageError::RecoveryRequired(
                "runtime cache belongs to another auth scope",
            ));
        }
        Ok(())
    }
    pub fn cleanup_snapshot(&self) -> Result<RuntimeCleanupSnapshotV1, StorageError> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        Ok(cleanup_snapshot(&self.load_required()?))
    }
    /// Container control only. The caller must hold runtime writer quiescence
    /// and present matching local/server receipts before invoking this method.
    pub fn complete_cleanup(&self, frozen: &RuntimeCleanupSnapshotV1) -> Result<(), StorageError> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let mut current = self.load_required()?;
        if cleanup_snapshot(&current) != *frozen {
            return Err(StorageError::RecoveryRequired(
                "runtime cleanup snapshot changed",
            ));
        }
        current.complete_legacy_cleanup();
        self.backend.save(&current)
    }
    /// Atomically clears and rebinds a same-record transition. This avoids an
    /// unrecoverable gap between destructive cleanup and target admission.
    pub fn complete_cleanup_and_bind(
        &self,
        frozen: &RuntimeCleanupSnapshotV1,
        scope: &RuntimeAuthScope,
    ) -> Result<(), StorageError> {
        scope.validate()?;
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let mut current = self.load_required()?;
        if !current.cleanup_only && current.auth_scope.as_ref() == Some(scope) {
            return Ok(());
        }
        if cleanup_snapshot(&current) != *frozen
            || current.slot != scope.identity.slot
            || current.runtime_version != scope.identity.runtime_version
        {
            return Err(StorageError::RecoveryRequired(
                "runtime cleanup snapshot changed",
            ));
        }
        current.complete_legacy_cleanup();
        current.auth_scope = Some(scope.clone());
        self.backend.save(&current)
    }
    /// Owner/control only: caller holds actual runtime-writer quiescence (or
    /// has not handed the record to any runtime yet). Never called by access reads.
    pub fn bind_empty_scope(&self, scope: &RuntimeAuthScope) -> Result<(), StorageError> {
        scope.validate()?;
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let mut current = self.load_required()?;
        if current.cleanup_only
            || !current.operationally_empty()
            || current.slot != scope.identity.slot
            || current.runtime_version != scope.identity.runtime_version
        {
            return Err(StorageError::RecoveryRequired(
                "runtime cleanup is required before auth admission",
            ));
        }
        current.auth_scope = Some(scope.clone());
        self.backend.save(&current)
    }
    fn load_required(&self) -> Result<RuntimeStateV1, StorageError> {
        self.backend
            .load()?
            .ok_or(StorageError::RecoveryRequired("missing runtime record"))
    }
}

pub struct RuntimeOperationalStore<S> {
    owner: Arc<RuntimeRecordOwner<S>>,
}
impl<S: RuntimeStateStore> RuntimeStateStore for RuntimeOperationalStore<S> {
    fn paths(&self) -> &RuntimePaths {
        self.owner.backend.paths()
    }
    fn load(&self) -> Result<Option<RuntimeStateV1>, StorageError> {
        let _guard = self
            .owner
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        self.owner.load_required().map(Some)
    }
    fn save(&self, value: &RuntimeStateV1) -> Result<(), StorageError> {
        let _guard = self
            .owner
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let mut current = self.owner.load_required()?;
        if value.schema_version != current.schema_version
            || value.auth_scope != current.auth_scope
            || value.slot != current.slot
            || value.runtime_version != current.runtime_version
        {
            return Err(StorageError::RecoveryRequired(
                "runtime schema or exact version mismatch",
            ));
        }
        current.saved_connection = value.saved_connection.clone();
        current.pinned_connection = value.pinned_connection.clone();
        current.pending_start = value.pending_start.clone();
        current.pending_stalled_stop = value.pending_stalled_stop.clone();
        current.pending_compensation_stop = value.pending_compensation_stop.clone();
        current.compatibility = value.compatibility.clone();
        self.owner.backend.save(&current)
    }
}

pub struct RuntimeSplitTunnelStore<S> {
    owner: Arc<RuntimeRecordOwner<S>>,
}
impl<S: RuntimeStateStore> crate::SplitTunnelStore for RuntimeSplitTunnelStore<S> {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError> {
        let _guard = self
            .owner
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        Ok(self.owner.load_required()?.applied_split_tunnel)
    }
    fn save(&self, value: &StoredSplitTunnelState) -> Result<(), StorageError> {
        let _guard = self
            .owner
            .gate
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("runtime owner lock poisoned"))?;
        let mut current = self.owner.load_required()?;
        current.applied_split_tunnel = crate::split_tunnel::normalized_checked_state(value)?;
        self.owner.backend.save(&current)
    }
    fn delete(&self) -> Result<(), StorageError> {
        self.save(&StoredSplitTunnelState::default())
    }
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
        if let Some(scope) = &value.auth_scope {
            scope.validate()?;
            if scope.identity.slot != value.slot
                || scope.identity.runtime_version != value.runtime_version
            {
                return Err(StorageError::RecoveryRequired(
                    "runtime auth scope target mismatch",
                ));
            }
        }
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
