//! Crash-resumable storage migration. Callers must hold the container's
//! single-instance lock across all reads/writes and bootstrap acknowledgement.
//! No in-process mutex here claims to serialize independent processes.
use crate::{
    atomic_private_write,
    auth::{decode_record, digest, encode_record, valid_digest},
    AuthStore, AuthStoreV1, LogoutState, ProtectedRecordStore, RuntimePaths, RuntimeStateStore,
    RuntimeStateV1, SecretStore, SplitTunnelStore, StorageError, StoredAuth,
    StoredSplitTunnelState, SystemSecretStore,
};
use nelomai_contracts::RuntimeIdentity;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    LegacyRead,
    AuthWritten,
    RuntimeWritten,
    Committed,
    Verified,
    Tombstoning,
    Complete,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationOutcome {
    NoLegacy,
    AwaitingBootstrap,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeMetadataV1 {
    pub operation_id: String,
    pub fingerprint: String,
    pub target_identity: RuntimeIdentity,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingWriteV1 {
    pub transaction_id: String,
    pub source_auth_sha256: String,
    pub source_runtime_sha256: String,
    pub auth_sha256: String,
    pub runtime_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRecord {
    pub schema_version: u32,
    pub phase: MigrationPhase,
    pub runtime_namespace: String,
    pub legacy_sha256: String,
    pub legacy_split_sha256: String,
    pub install_sha256: String,
    pub baseline_auth_sha256: String,
    pub baseline_runtime_sha256: String,
    pub pending_write: Option<PendingWriteV1>,
    pub last_transaction_id: Option<String>,
    pub pending_resume: Option<ResumeMetadataV1>,
    pub confirmed_identity: Option<RuntimeIdentity>,
}
pub trait MigrationJournal: Send + Sync {
    fn load(&self) -> Result<Option<MigrationRecord>, StorageError>;
    fn save(&self, record: &MigrationRecord) -> Result<(), StorageError>;
}
pub struct FileMigrationJournal {
    path: PathBuf,
}
impl FileMigrationJournal {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().into(),
        }
    }
}
impl MigrationJournal for FileMigrationJournal {
    fn load(&self) -> Result<Option<MigrationRecord>, StorageError> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let value = decode_record(&bytes, "migration-v1")?;
                validate_record(&value)?;
                Ok(Some(value))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn save(&self, record: &MigrationRecord) -> Result<(), StorageError> {
        validate_record(record)?;
        atomic_private_write(&self.path, &encode_record(record, "migration-v1")?)
    }
}
fn validate_record(record: &MigrationRecord) -> Result<(), StorageError> {
    if record.schema_version != 1
        || record.runtime_namespace.is_empty()
        || [
            &record.legacy_sha256,
            &record.legacy_split_sha256,
            &record.install_sha256,
            &record.baseline_auth_sha256,
            &record.baseline_runtime_sha256,
        ]
        .iter()
        .any(|v| !valid_digest(v))
    {
        return Err(StorageError::RecoveryRequired("invalid migration metadata"));
    }
    if let Some(pending) = &record.pending_write {
        if [
            &pending.transaction_id,
            &pending.source_auth_sha256,
            &pending.source_runtime_sha256,
            &pending.auth_sha256,
            &pending.runtime_sha256,
        ]
        .iter()
        .any(|v| !valid_digest(v))
        {
            return Err(StorageError::RecoveryRequired(
                "invalid pending store write",
            ));
        }
    }
    Ok(())
}

pub struct LegacyMigrationSource<'a> {
    auth: &'a dyn SecretStore,
    split: &'a dyn SplitTunnelStore,
}
impl<'a> LegacyMigrationSource<'a> {
    pub fn new(auth: &'a dyn SecretStore, split: &'a dyn SplitTunnelStore) -> Self {
        Self { auth, split }
    }
}

fn required<T>(value: Option<T>) -> Result<T, StorageError> {
    value.ok_or(StorageError::RecoveryRequired(
        "required migration record is missing",
    ))
}
fn metadata(record: &mut MigrationRecord, auth: &AuthStoreV1) {
    record.pending_resume = auth.pending_resume.as_ref().map(|p| ResumeMetadataV1 {
        operation_id: p.operation_id.clone(),
        fingerprint: p.fingerprint.clone(),
        target_identity: p.target_identity.clone(),
    });
    record.confirmed_identity = auth.confirmed_identity.clone();
}
fn pair(
    record: &MigrationRecord,
    auth: &AuthStoreV1,
    runtime: &RuntimeStateV1,
    store: &dyn RuntimeStateStore,
) -> Result<(), StorageError> {
    validate_record(record)?;
    if record.runtime_namespace != store.paths().namespace()
        || record.install_sha256 != digest(&auth.install_secret)?
        || runtime.schema_version != 1
        || runtime.slot != store.paths().slot()
        || runtime.runtime_version != store.paths().runtime_version()
    {
        return Err(StorageError::RecoveryRequired(
            "migration identity or runtime namespace changed",
        ));
    }
    if record.pending_write.is_some() {
        return Err(StorageError::RecoveryRequired(
            "interrupted two-store update requires protected replay",
        ));
    }
    Ok(())
}
fn baseline(
    record: &MigrationRecord,
    auth: &AuthStoreV1,
    runtime: Option<&RuntimeStateV1>,
) -> Result<(), StorageError> {
    if digest(auth)? != record.baseline_auth_sha256
        || runtime.is_some_and(|v| digest(v).ok().as_ref() != Some(&record.baseline_runtime_sha256))
    {
        return Err(StorageError::RecoveryRequired(
            "incomplete migration record changed",
        ));
    }
    Ok(())
}

/// Reads the explicit legacy split-tunnel store as well as the auth store.
/// Errors are recoverable and must never be converted to `new_install()`.
pub fn migrate_legacy_auth(
    source: &LegacyMigrationSource<'_>,
    auth_store: &dyn AuthStore,
    runtime_store: &dyn RuntimeStateStore,
    journal: &dyn MigrationJournal,
) -> Result<MigrationOutcome, StorageError> {
    let mut auth = auth_store.load()?;
    let mut runtime = runtime_store.load()?;
    let existing = journal.load()?;
    if let Some(mut record) = existing.clone() {
        if matches!(
            record.phase,
            MigrationPhase::Verified | MigrationPhase::Tombstoning | MigrationPhase::Complete
        ) {
            let current = required(auth)?;
            let state = required(runtime)?;
            pair(&record, &current, &state, runtime_store)?;
            metadata(&mut record, &current);
            journal.save(&record)?;
            return if record.phase == MigrationPhase::Tombstoning {
                acknowledge_migration_bootstrap(source, auth_store, runtime_store, journal)
            } else {
                Ok(if record.phase == MigrationPhase::Complete {
                    MigrationOutcome::Complete
                } else {
                    MigrationOutcome::AwaitingBootstrap
                })
            };
        }
    }
    let Some(legacy) = source.auth.load()? else {
        if existing.is_some() || auth.is_some() || runtime.is_some() {
            return Err(StorageError::RecoveryRequired(
                "legacy source missing during migration",
            ));
        }
        return Ok(MigrationOutcome::NoLegacy);
    };
    let split = source.split.load()?;
    let expected_auth = AuthStoreV1::from_legacy(&legacy);
    expected_auth.validate()?;
    let expected_runtime =
        RuntimeStateV1::import_legacy(&legacy, split.clone(), runtime_store.paths());
    let legacy_sha = digest(&(&legacy, &split))?;
    let mut record = match existing {
        Some(record) => {
            validate_record(&record)?;
            if record.legacy_sha256 != legacy_sha
                || record.runtime_namespace != runtime_store.paths().namespace()
                || record.baseline_auth_sha256 != digest(&expected_auth)?
                || record.baseline_runtime_sha256 != digest(&expected_runtime)?
            {
                return Err(StorageError::RecoveryRequired(
                    "legacy migration source changed",
                ));
            }
            record
        }
        None => {
            if auth.is_some() || runtime.is_some() {
                return Err(StorageError::RecoveryRequired(
                    "new records exist without migration provenance",
                ));
            }
            let record = MigrationRecord {
                schema_version: 1,
                phase: MigrationPhase::LegacyRead,
                runtime_namespace: runtime_store.paths().namespace().into(),
                legacy_sha256: legacy_sha,
                legacy_split_sha256: digest(&split)?,
                install_sha256: digest(&legacy.install_secret)?,
                baseline_auth_sha256: digest(&expected_auth)?,
                baseline_runtime_sha256: digest(&expected_runtime)?,
                pending_write: None,
                last_transaction_id: None,
                pending_resume: None,
                confirmed_identity: None,
            };
            journal.save(&record)?;
            record
        }
    };
    if record.phase == MigrationPhase::LegacyRead {
        if let Some(value) = &auth {
            baseline(&record, value, None)?;
        } else {
            auth_store.save(&expected_auth)?;
            auth = Some(expected_auth.clone());
        }
        record.phase = MigrationPhase::AuthWritten;
        journal.save(&record)?;
    }
    baseline(&record, &required(auth.clone())?, None)?;
    if record.phase == MigrationPhase::AuthWritten {
        if let Some(value) = &runtime {
            baseline(&record, &expected_auth, Some(value))?;
        } else {
            runtime_store.save(&expected_runtime)?;
            runtime = Some(expected_runtime);
        }
        record.phase = MigrationPhase::RuntimeWritten;
        journal.save(&record)?;
    }
    baseline(&record, &required(auth)?, Some(&required(runtime)?))?;
    if record.phase == MigrationPhase::RuntimeWritten {
        record.phase = MigrationPhase::Committed;
        journal.save(&record)?;
    }
    if record.phase == MigrationPhase::Committed {
        baseline(
            &record,
            &required(auth_store.load()?)?,
            Some(&required(runtime_store.load()?)?),
        )?;
        record.phase = MigrationPhase::Verified;
        journal.save(&record)?;
    }
    Ok(MigrationOutcome::AwaitingBootstrap)
}

/// Explicit delayed bootstrap acknowledgement. Network enrollment/cleanup is
/// performed by the broker; this method only checks its durable storage proof.
pub fn acknowledge_migration_bootstrap(
    source: &LegacyMigrationSource<'_>,
    auth_store: &dyn AuthStore,
    runtime_store: &dyn RuntimeStateStore,
    journal: &dyn MigrationJournal,
) -> Result<MigrationOutcome, StorageError> {
    let mut record = required(journal.load()?)?;
    let auth = required(auth_store.load()?)?;
    let runtime = required(runtime_store.load()?)?;
    pair(&record, &auth, &runtime, runtime_store)?;
    if record.phase == MigrationPhase::Complete {
        return Ok(MigrationOutcome::Complete);
    }
    if !matches!(
        record.phase,
        MigrationPhase::Verified | MigrationPhase::Tombstoning
    ) {
        return Err(StorageError::RecoveryRequired("migration is not verified"));
    }
    let identity = auth
        .confirmed_identity
        .as_ref()
        .ok_or(StorageError::RecoveryRequired(
            "bootstrap enrollment not acknowledged",
        ))?;
    if auth.session_generation.is_none()
        || identity.session_generation != auth.session_generation
        || identity.slot != runtime.slot
        || identity.runtime_version != runtime.runtime_version
        || auth.logout_state != LogoutState::Active
        || runtime.cleanup_only
        || runtime.saved_connection.is_some()
        || runtime.pinned_connection.is_some()
        || runtime.pending_start.is_some()
        || runtime.pending_stalled_stop.is_some()
        || runtime.pending_compensation_stop.is_some()
        || runtime.applied_split_tunnel != StoredSplitTunnelState::default()
    {
        return Err(StorageError::RecoveryRequired(
            "legacy cleanup or enrollment remains pending",
        ));
    }
    let tombstone = StoredAuth {
        install_secret: auth.install_secret.clone(),
        access_token: None,
        refresh_token: None,
        saved_connection: None,
        pinned_connection: None,
        pending_start: None,
        pending_stalled_stop: None,
        pending_compensation_stop: None,
        compatibility: None,
    };
    let legacy = required(source.auth.load()?)?;
    let split = source.split.load()?;
    let intact = digest(&(&legacy, &split))? == record.legacy_sha256;
    let partial = record.phase == MigrationPhase::Tombstoning
        && legacy == tombstone
        && (digest(&split)? == record.legacy_split_sha256
            || split == StoredSplitTunnelState::default());
    if !intact && !partial {
        return Err(StorageError::RecoveryRequired(
            "legacy source changed before tombstone",
        ));
    }
    if record.phase == MigrationPhase::Verified {
        record.phase = MigrationPhase::Tombstoning;
        metadata(&mut record, &auth);
        journal.save(&record)?;
    }
    source.auth.save(&tombstone)?;
    source.split.delete()?;
    if source.auth.load()?.as_ref() != Some(&tombstone)
        || source.split.load()? != StoredSplitTunnelState::default()
    {
        return Err(StorageError::RecoveryRequired(
            "legacy tombstone verification failed",
        ));
    }
    record.phase = MigrationPhase::Complete;
    journal.save(&record)?;
    Ok(MigrationOutcome::Complete)
}

/// Broker/container-only compatibility adapter, NEVER runtime-process IPC.
/// The caller holds the single-instance lock and completes migration/cleanup
/// first. An absent or interrupted migration returns an error, never None.
pub struct RuntimeStorageSession<'a> {
    auth: &'a dyn AuthStore,
    runtime: &'a dyn RuntimeStateStore,
    journal: &'a dyn MigrationJournal,
    staging: &'a dyn StorageTransactionStore,
    observed_epoch: Mutex<Option<u64>>,
}
impl<'a> RuntimeStorageSession<'a> {
    pub fn new(
        auth: &'a dyn AuthStore,
        runtime: &'a dyn RuntimeStateStore,
        journal: &'a dyn MigrationJournal,
        staging: &'a dyn StorageTransactionStore,
    ) -> Self {
        Self {
            auth,
            runtime,
            journal,
            staging,
            observed_epoch: Mutex::new(None),
        }
    }
    fn recover_transaction(&self, record: &mut MigrationRecord) -> Result<(), StorageError> {
        let Some(target) = self.staging.load()? else {
            return if record.pending_write.is_some() {
                Err(StorageError::RecoveryRequired(
                    "protected transaction payload is missing",
                ))
            } else {
                Ok(())
            };
        };
        let intent = target.intent()?;
        if record.pending_write.is_none()
            && record.last_transaction_id.as_ref() == Some(&target.transaction_id)
        {
            return self.staging.clear();
        }
        if !matches!(
            record.phase,
            MigrationPhase::Verified | MigrationPhase::Complete
        ) || record.runtime_namespace != self.runtime.paths().namespace()
            || target.runtime.slot != self.runtime.paths().slot()
            || target.runtime.runtime_version != self.runtime.paths().runtime_version()
            || target.runtime.cleanup_only
            || digest(&target.auth.install_secret)? != record.install_sha256
        {
            return Err(StorageError::RecoveryRequired(
                "transaction does not match migrated owners",
            ));
        }
        if record
            .pending_write
            .as_ref()
            .is_some_and(|value| value != &intent)
        {
            return Err(StorageError::RecoveryRequired(
                "transaction journal disagrees with protected payload",
            ));
        }
        let current_auth = digest(&required(self.auth.load()?)?)?;
        let current_runtime = digest(&required(self.runtime.load()?)?)?;
        if ![&intent.source_auth_sha256, &intent.auth_sha256].contains(&&current_auth)
            || ![&intent.source_runtime_sha256, &intent.runtime_sha256].contains(&&current_runtime)
        {
            return Err(StorageError::RecoveryRequired(
                "owners advanced after staged transaction; refusing rollback",
            ));
        }
        if record.pending_write.is_none() {
            record.pending_write = Some(intent.clone());
            self.journal.save(record)?;
        }
        if current_auth != intent.auth_sha256 {
            self.auth.save(&target.auth)?;
        }
        if current_runtime != intent.runtime_sha256 {
            self.runtime.save(&target.runtime)?;
        }
        if digest(&required(self.auth.load()?)?)? != intent.auth_sha256
            || digest(&required(self.runtime.load()?)?)? != intent.runtime_sha256
        {
            return Err(StorageError::RecoveryRequired(
                "transaction owner verification failed",
            ));
        }
        record.pending_write = None;
        record.last_transaction_id = Some(target.transaction_id);
        metadata(record, &target.auth);
        self.journal.save(record)?;
        self.staging.clear()
    }
}
impl SecretStore for RuntimeStorageSession<'_> {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        let mut record = required(self.journal.load()?)?;
        self.recover_transaction(&mut record)?;
        let auth = required(self.auth.load()?)?;
        let runtime = required(self.runtime.load()?)?;
        pair(&record, &auth, &runtime, self.runtime)?;
        if !matches!(
            record.phase,
            MigrationPhase::Verified | MigrationPhase::Complete
        ) || runtime.cleanup_only
        {
            return Err(StorageError::RecoveryRequired(
                "legacy cleanup must complete before projection",
            ));
        }
        *self
            .observed_epoch
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("storage session unavailable"))? =
            Some(auth.auth_epoch);
        Ok(Some(runtime.project(&auth)))
    }
    fn save(&self, value: &StoredAuth) -> Result<(), StorageError> {
        let mut record = required(self.journal.load()?)?;
        self.recover_transaction(&mut record)?;
        let mut auth = required(self.auth.load()?)?;
        let mut runtime = required(self.runtime.load()?)?;
        pair(&record, &auth, &runtime, self.runtime)?;
        let epoch = *self
            .observed_epoch
            .lock()
            .map_err(|_| StorageError::RecoveryRequired("storage session unavailable"))?;
        if epoch != Some(auth.auth_epoch)
            || auth.install_secret != value.install_secret
            || runtime.cleanup_only
            || !matches!(
                record.phase,
                MigrationPhase::Verified | MigrationPhase::Complete
            )
            || (auth.logout_state != LogoutState::Active
                && (value.access_token.is_some() || value.refresh_token.is_some()))
        {
            return Err(StorageError::RecoveryRequired(
                "stale or unavailable storage projection",
            ));
        }
        let source_auth_sha256 = digest(&auth)?;
        let source_runtime_sha256 = digest(&runtime)?;
        auth.access_token = value.access_token.clone();
        auth.refresh_token = value.refresh_token.clone();
        runtime.save_projection(value);
        let transaction_id = digest(&(
            &source_auth_sha256,
            &source_runtime_sha256,
            digest(&auth)?,
            digest(&runtime)?,
        ))?;
        self.staging.save(&PendingStorageTransaction {
            schema_version: 1,
            transaction_id,
            source_auth_sha256,
            source_runtime_sha256,
            auth,
            runtime,
        })?;
        self.recover_transaction(&mut record)
    }
    fn delete(&self) -> Result<(), StorageError> {
        Err(StorageError::RecoveryRequired(
            "broker logout acknowledgement required",
        ))
    }
}

/// Protected, bounded write-ahead target. Includes credentials and tunnel data;
/// never serialize this value to the nonsecret journal or runtime IPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingStorageTransaction {
    pub schema_version: u32,
    pub transaction_id: String,
    pub source_auth_sha256: String,
    pub source_runtime_sha256: String,
    pub auth: AuthStoreV1,
    pub runtime: RuntimeStateV1,
}
impl PendingStorageTransaction {
    fn intent(&self) -> Result<PendingWriteV1, StorageError> {
        self.auth.validate()?;
        let auth_sha256 = digest(&self.auth)?;
        let runtime_sha256 = digest(&self.runtime)?;
        if self.schema_version != 1
            || !valid_digest(&self.source_auth_sha256)
            || !valid_digest(&self.source_runtime_sha256)
            || self.transaction_id
                != digest(&(
                    &self.source_auth_sha256,
                    &self.source_runtime_sha256,
                    &auth_sha256,
                    &runtime_sha256,
                ))?
        {
            return Err(StorageError::RecoveryRequired(
                "invalid protected transaction",
            ));
        }
        Ok(PendingWriteV1 {
            transaction_id: self.transaction_id.clone(),
            source_auth_sha256: self.source_auth_sha256.clone(),
            source_runtime_sha256: self.source_runtime_sha256.clone(),
            auth_sha256,
            runtime_sha256,
        })
    }
}
pub trait StorageTransactionStore: Send + Sync {
    fn load(&self) -> Result<Option<PendingStorageTransaction>, StorageError>;
    fn save(&self, value: &PendingStorageTransaction) -> Result<(), StorageError>;
    fn clear(&self) -> Result<(), StorageError>;
}
pub struct ProtectedTransactionStore<R> {
    record: R,
    namespace: String,
}
impl<R: ProtectedRecordStore> ProtectedTransactionStore<R> {
    pub fn new(record: R, paths: RuntimePaths) -> Self {
        Self {
            record,
            namespace: format!("{}:pending-write-v1", paths.namespace()),
        }
    }
}
impl ProtectedTransactionStore<SystemSecretStore> {
    pub fn system(
        legacy_account: &str,
        linux_fallback_dir: Option<PathBuf>,
        paths: RuntimePaths,
    ) -> Self {
        let account = format!("{legacy_account}:{}:pending-write-v1", paths.namespace());
        Self::new(SystemSecretStore::new(account, linux_fallback_dir), paths)
    }
}
impl<R: ProtectedRecordStore> StorageTransactionStore for ProtectedTransactionStore<R> {
    fn load(&self) -> Result<Option<PendingStorageTransaction>, StorageError> {
        self.record
            .load_record()?
            .map(|bytes| {
                if bytes.len() > 8 * 1024 * 1024 {
                    return Err(StorageError::RecoveryRequired(
                        "protected transaction exceeds limit",
                    ));
                }
                let value: PendingStorageTransaction = decode_record(&bytes, &self.namespace)?;
                value.intent()?;
                Ok(value)
            })
            .transpose()
    }
    fn save(&self, value: &PendingStorageTransaction) -> Result<(), StorageError> {
        value.intent()?;
        let bytes = encode_record(value, &self.namespace)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(StorageError::RecoveryRequired(
                "protected transaction exceeds limit",
            ));
        }
        self.record.save_record(&bytes)
    }
    fn clear(&self) -> Result<(), StorageError> {
        self.record.delete_record()
    }
}
