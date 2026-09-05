//! Locked startup only. Reachable runtime-v1 inventory is internally derived:
//! first supported maintenance namespaces, signed manifest and durable anchors.
//! Keyrings cannot enumerate arbitrary orphan accounts after external deletion
//! of every anchor; this is not a generic namespace scan or recovery product.
use crate::{
    auth::{decode_record, digest, encode_record, valid_digest},
    *,
};
use nelomai_contracts::{RuntimeSlot, VerifiedContainerManifest};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

pub trait ProtectedRecordFactory {
    type Record: ProtectedRecordStore;
    fn record(&self, namespace: &str) -> Self::Record;
    fn legacy(&self) -> &dyn SecretStore;
}
pub struct SystemRecordFactory {
    legacy: SystemSecretStore,
    account: String,
    fallback: Option<PathBuf>,
}
impl SystemRecordFactory {
    /// Construct only after the common owner lock and manifest verification.
    pub fn new(account: &str, fallback: Option<PathBuf>) -> Self {
        Self {
            legacy: SystemSecretStore::new(account, fallback.clone()),
            account: account.into(),
            fallback,
        }
    }
}
impl ProtectedRecordFactory for SystemRecordFactory {
    type Record = SystemSecretStore;
    fn record(&self, namespace: &str) -> Self::Record {
        SystemSecretStore::new(
            format!("{}:{namespace}", self.account),
            self.fallback.clone(),
        )
    }
    fn legacy(&self) -> &dyn SecretStore {
        &self.legacy
    }
}

pub struct PreparedRuntimeStorage<R> {
    pub auth: ProtectedAuthStore<R>,
    pub runtime: ProtectedRuntimeStore<R>,
    pub retained: Vec<ProtectedRuntimeStore<R>>,
    pub migration: Option<MigrationOutcome>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema_version: u32,
    namespaces: Vec<String>,
    install_sha256: String,
    fresh_transaction_id: Option<String>,
    committed: bool,
}
fn recovery<T>() -> Result<T, StorageError> {
    Err(StorageError::RecoveryRequired(
        "startup inventory requires recovery",
    ))
}
fn inventory_path(root: &Path) -> PathBuf {
    root.join("common/runtime-inventory-v1.json")
}
fn read_inventory(root: &Path) -> Result<Option<Inventory>, StorageError> {
    let path = inventory_path(root);
    let bytes = match fs::read(path) {
        Ok(bytes) if bytes.len() <= 64 * 1024 => bytes,
        Ok(_) => return recovery(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let marker: Inventory = decode_record(&bytes, "runtime-inventory-v1")?;
    if marker.schema_version != 1
        || marker.namespaces.is_empty()
        || marker.namespaces.len() > 64
        || !valid_digest(&marker.install_sha256)
        || marker
            .fresh_transaction_id
            .as_ref()
            .is_some_and(|v| !valid_digest(v))
        || (!marker.committed && marker.fresh_transaction_id.is_none())
    {
        return recovery();
    }
    Ok(Some(marker))
}
fn write_inventory(root: &Path, marker: &Inventory) -> Result<(), StorageError> {
    atomic_private_write(
        &inventory_path(root),
        &encode_record(marker, "runtime-inventory-v1")?,
    )
}
fn paths_from_namespace(root: &Path, namespace: &str) -> Result<RuntimePaths, StorageError> {
    let parts: Vec<_> = namespace.split('/').collect();
    if parts.len() != 5
        || parts[0] != "runtime"
        || parts[2] != "state"
        || parts[4] != "state-v1.json"
    {
        return recovery();
    }
    let slot = match parts[1] {
        "latest" => RuntimeSlot::Latest,
        "stable" => RuntimeSlot::Stable,
        _ => return recovery(),
    };
    let paths = RuntimePaths::new(root, slot, parts[3])?;
    if paths.namespace() != namespace {
        return recovery();
    }
    Ok(paths)
}

/// Must run before any broker or writable runtime view is handed out. It never
/// converts corrupt/missing anchors to new_install and never clears cleanup_only.
pub fn prepare_runtime_storage<F: ProtectedRecordFactory>(
    lock: &ContainerOwnerLock,
    manifest: &VerifiedContainerManifest,
    selected: RuntimeSlot,
    records: &F,
) -> Result<PreparedRuntimeStorage<F::Record>, StorageError> {
    let root = lock.root();
    let target = manifest
        .identity(selected, None)
        .map_err(|_| StorageError::RecoveryRequired("unavailable installed runtime selection"))?;
    let selected_paths = RuntimePaths::new(root, selected, &target.runtime_version)?;
    let auth = ProtectedAuthStore::new(records.record("auth-v1"));
    let runtime = ProtectedRuntimeStore::new(
        records.record(selected_paths.namespace()),
        selected_paths.clone(),
    );
    let journal = FileMigrationJournal::new(root.join("common/auth-migration-v1.json"));
    let migration_record = journal.load()?;
    let marker = read_inventory(root)?;
    let mut known = BTreeSet::new();
    // 0.2.16 is the first shipped runtime-v1 storage schema. These accounts
    // remain reachable even if a later manifest omits that maintenance version.
    for slot in [RuntimeSlot::Latest, RuntimeSlot::Stable] {
        known.insert(
            RuntimePaths::new(root, slot, "0.2.16")?
                .namespace()
                .to_owned(),
        );
    }
    for slot in &manifest.manifest().slots {
        known.insert(
            RuntimePaths::new(root, slot.slot, &slot.manifest.runtime_version)?
                .namespace()
                .to_owned(),
        );
    }
    if let Some(marker) = &marker {
        for namespace in &marker.namespaces {
            paths_from_namespace(root, namespace)?;
            if !known.insert(namespace.clone())
                && marker.namespaces.iter().filter(|v| *v == namespace).count() != 1
            {
                return recovery();
            }
        }
    }
    if let Some(record) = &migration_record {
        paths_from_namespace(root, &record.runtime_namespace)?;
        known.insert(record.runtime_namespace.clone());
        if record.runtime_namespace != selected_paths.namespace()
            && record.phase != MigrationPhase::Complete
        {
            return recovery();
        }
    }
    if known.len() > 64 {
        return recovery();
    }
    let mut occupied = Vec::new();
    let mut pending = Vec::new();
    for namespace in &known {
        let paths = paths_from_namespace(root, namespace)?;
        let state = ProtectedRuntimeStore::new(records.record(namespace), paths.clone());
        if state.load()?.is_some() {
            occupied.push(namespace.clone());
        }
        let staging = ProtectedTransactionStore::new(
            records.record(&format!("{namespace}:pending-write-v1")),
            paths,
        );
        if let Some(value) = staging.load()? {
            pending.push((namespace.clone(), value));
        }
    }
    let current_auth = auth.load()?;
    let split = FileSplitTunnelStore::new(root);
    let split_exists = match fs::symlink_metadata(split.path()) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let legacy = records.legacy().load()?;
    let staging = ProtectedTransactionStore::new(
        records.record(&format!("{}:pending-write-v1", selected_paths.namespace())),
        selected_paths.clone(),
    );
    let mut inventory_namespaces: BTreeSet<String> = marker
        .as_ref()
        .map(|marker| marker.namespaces.iter().cloned().collect())
        .unwrap_or_default();
    inventory_namespaces.extend(occupied.iter().cloned());
    inventory_namespaces.insert(selected_paths.namespace().to_owned());
    let namespaces: Vec<_> = inventory_namespaces.into_iter().collect();
    let migration_complete = migration_record
        .as_ref()
        .is_some_and(|record| record.phase == MigrationPhase::Complete);
    if migration_complete && split_exists {
        return recovery();
    }
    if !migration_complete && (legacy.is_some() || migration_record.is_some()) {
        // A legacy source is not provenance for another occupied runtime.
        // Only a committed common inventory can anchor those retained records.
        if occupied.iter().any(|namespace| {
            namespace != selected_paths.namespace()
                && !marker
                    .as_ref()
                    .is_some_and(|m| m.committed && m.namespaces.contains(namespace))
        }) {
            return recovery();
        }
        if marker
            .as_ref()
            .is_some_and(|m| !m.committed || m.fresh_transaction_id.is_some())
        {
            return recovery();
        }
        if !pending.is_empty() {
            if pending.len() != 1
                || pending[0].0 != selected_paths.namespace()
                || migration_record.is_none()
            {
                return recovery();
            }
            // Only startup compatibility replay; no adapter survives handoff.
            RuntimeStorageSession::new(&auth, &runtime, &journal, &staging).load()?;
        }
        let outcome = migrate_legacy_auth(
            &LegacyMigrationSource::new(records.legacy(), &split),
            &auth,
            &runtime,
            &journal,
        )?;
        let install = auth
            .load()?
            .ok_or(StorageError::RecoveryRequired("migration auth missing"))?;
        if marker.as_ref().is_some_and(|m| {
            digest(&install.install_secret).ok().as_ref() != Some(&m.install_sha256)
        }) {
            return recovery();
        }
        write_inventory(
            root,
            &Inventory {
                schema_version: 1,
                namespaces,
                install_sha256: digest(&install.install_secret)?,
                fresh_transaction_id: None,
                committed: true,
            },
        )?;
        return Ok(PreparedRuntimeStorage {
            auth,
            runtime,
            retained: retained_runtime_stores(
                records,
                root,
                &occupied,
                selected_paths.namespace(),
            )?,
            migration: Some(outcome),
        });
    }
    if split_exists {
        return recovery();
    }
    if let Some(marker) = &marker {
        if marker.committed {
            let current =
                current_auth.ok_or(StorageError::RecoveryRequired("common auth anchor missing"))?;
            if digest(&current.install_secret)? != marker.install_sha256 {
                return recovery();
            }
            let expected_new_runtime = RuntimeStateV1::empty(&selected_paths, true);
            let current_runtime = runtime.load()?;
            if occupied.iter().any(|namespace| {
                namespace != selected_paths.namespace() && !marker.namespaces.contains(namespace)
            }) || current_runtime.as_ref().is_some_and(|state| {
                !marker
                    .namespaces
                    .contains(&selected_paths.namespace().to_owned())
                    && state != &expected_new_runtime
            }) {
                return recovery();
            }
            if current_runtime.is_none() {
                if marker
                    .namespaces
                    .iter()
                    .any(|namespace| namespace == selected_paths.namespace())
                    || occupied.is_empty()
                    || !pending.is_empty()
                {
                    return recovery();
                }
                runtime.save(&expected_new_runtime)?;
            }
            if !pending.is_empty() {
                if pending.len() != 1
                    || pending[0].0 != selected_paths.namespace()
                    || Some(&pending[0].1.transaction_id) != marker.fresh_transaction_id.as_ref()
                {
                    return recovery();
                }
                // A committed staging residue must never rewind newer broker data.
                staging.clear()?;
            }
            write_inventory(
                root,
                &Inventory {
                    namespaces,
                    ..marker.clone()
                },
            )?;
            return Ok(PreparedRuntimeStorage {
                auth,
                runtime,
                retained: retained_runtime_stores(
                    records,
                    root,
                    &occupied,
                    selected_paths.namespace(),
                )?,
                migration: None,
            });
        }
    }
    let absent = digest(&Option::<()>::None)?;
    let transaction = if pending.is_empty() {
        if marker.is_some() || current_auth.is_some() || !occupied.is_empty() {
            return recovery();
        }
        let new_install = StoredAuth::new_install();
        let new_auth = AuthStoreV1::from_legacy(&new_install);
        let mut new_runtime = RuntimeStateV1::import_legacy(
            &new_install,
            StoredSplitTunnelState::default(),
            &selected_paths,
        );
        // Positively absent supported inventory permits a fresh empty record;
        // this is not resetting an imported cleanup barrier.
        new_runtime.cleanup_only = false;
        let transaction = PendingStorageTransaction {
            schema_version: 1,
            transaction_id: digest(&(&absent, &absent, digest(&new_auth)?, digest(&new_runtime)?))?,
            source_auth_sha256: absent.clone(),
            source_runtime_sha256: absent.clone(),
            auth: new_auth,
            runtime: new_runtime,
        };
        staging.save(&transaction)?;
        transaction
    } else {
        if pending.len() != 1 || pending[0].0 != selected_paths.namespace() {
            return recovery();
        }
        pending.remove(0).1
    };
    if transaction.source_auth_sha256 != absent
        || transaction.source_runtime_sha256 != absent
        || transaction.runtime.slot != selected_paths.slot()
        || transaction.runtime.runtime_version != selected_paths.runtime_version()
        || !transaction.runtime.operationally_empty()
        || transaction.runtime.cleanup_only
        || transaction.runtime.auth_scope.is_some()
        || transaction.auth.access_token.is_some()
        || transaction.auth.refresh_token.is_some()
        || transaction.auth.broker.is_some()
        || transaction.auth.confirmed_identity.is_some()
        || transaction.auth.auth_epoch != 0
        || transaction.auth.pending_resume.is_some()
        || transaction.auth.session_generation.is_some()
        || transaction.auth.logout_state != LogoutState::Active
        || occupied.iter().any(|v| v != selected_paths.namespace())
    {
        return recovery();
    }
    let install_sha256 = digest(&transaction.auth.install_secret)?;
    if marker.as_ref().is_some_and(|m| {
        m.install_sha256 != install_sha256
            || m.fresh_transaction_id.as_ref() != Some(&transaction.transaction_id)
    }) || current_auth
        .as_ref()
        .is_some_and(|a| a != &transaction.auth)
        || runtime
            .load()?
            .as_ref()
            .is_some_and(|r| r != &transaction.runtime)
    {
        return recovery();
    }
    let mut marker = Inventory {
        schema_version: 1,
        namespaces,
        install_sha256,
        fresh_transaction_id: Some(transaction.transaction_id.clone()),
        committed: false,
    };
    write_inventory(root, &marker)?;
    auth.save(&transaction.auth)?;
    runtime.save(&transaction.runtime)?;
    if auth.load()?.as_ref() != Some(&transaction.auth)
        || runtime.load()?.as_ref() != Some(&transaction.runtime)
    {
        return recovery();
    }
    marker.committed = true;
    write_inventory(root, &marker)?;
    staging.clear()?;
    Ok(PreparedRuntimeStorage {
        auth,
        runtime,
        retained: Vec::new(),
        migration: None,
    })
}

fn retained_runtime_stores<F: ProtectedRecordFactory>(
    records: &F,
    root: &Path,
    occupied: &[String],
    selected_namespace: &str,
) -> Result<Vec<ProtectedRuntimeStore<F::Record>>, StorageError> {
    occupied
        .iter()
        .filter(|namespace| namespace.as_str() != selected_namespace)
        .map(|namespace| {
            Ok(ProtectedRuntimeStore::new(
                records.record(namespace),
                paths_from_namespace(root, namespace)?,
            ))
        })
        .collect()
}
