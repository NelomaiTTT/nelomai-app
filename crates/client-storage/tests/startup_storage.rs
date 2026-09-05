use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_storage::*;
use nelomai_contracts::{
    verify_container_manifest, RuntimeSlot, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

#[derive(Clone, Default)]
struct Records {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    writes: Arc<AtomicUsize>,
    fail_at: Arc<AtomicUsize>,
    legacy: Legacy,
}
#[derive(Clone, Default)]
struct Legacy(Arc<Mutex<Option<StoredAuth>>>);
impl SecretStore for Legacy {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, value: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
    fn delete(&self) -> Result<(), StorageError> {
        panic!("startup cannot delete install identity")
    }
}
struct Record {
    key: String,
    all: Records,
}
impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.all.values.lock().unwrap().get(&self.key).cloned())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let count = self.all.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if self.all.fail_at.load(Ordering::SeqCst) == count {
            return Err(StorageError::RecoveryRequired(
                "synthetic interrupted write",
            ));
        }
        self.all
            .values
            .lock()
            .unwrap()
            .insert(self.key.clone(), bytes.into());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        self.all.values.lock().unwrap().remove(&self.key);
        Ok(())
    }
}
impl ProtectedRecordFactory for Records {
    type Record = Record;
    fn record(&self, namespace: &str) -> Self::Record {
        Record {
            key: namespace.into(),
            all: self.clone(),
        }
    }
    fn legacy(&self) -> &dyn SecretStore {
        &self.legacy
    }
}
fn manifest() -> nelomai_contracts::VerifiedContainerManifest {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/runtime/container-manifest-v1.json"
    ))
    .unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    let key = SigningKey::from_bytes(&[83; 32]);
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&bytes);
    let platform = value["slots"][0]["manifest"]["platform"].as_str().unwrap();
    let arch = value["slots"][0]["manifest"]["architecture"]
        .as_str()
        .unwrap();
    verify_container_manifest(
        &bytes,
        &key.sign(&message).to_bytes(),
        &key.verifying_key().to_bytes(),
        platform,
        arch,
    )
    .unwrap()
}

#[test]
fn fresh_pair_replays_original_protected_identity_after_each_owner_write_failure() {
    for fail_at in [2, 3] {
        let root = tempfile::tempdir().unwrap();
        let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
        let records = Records::default();
        records.fail_at.store(fail_at, Ordering::SeqCst);
        let manifest = manifest();
        assert!(prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).is_err());
        let path = RuntimePaths::new(
            root.path(),
            RuntimeSlot::Latest,
            manifest.latest().runtime_version.as_str(),
        )
        .unwrap();
        let staging = ProtectedTransactionStore::new(
            records.record(&format!("{}:pending-write-v1", path.namespace())),
            path,
        );
        let original = staging.load().unwrap().unwrap();
        records.fail_at.store(0, Ordering::SeqCst);
        let ready =
            prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).unwrap();
        assert_eq!(
            ready.auth.load().unwrap().unwrap().install_secret,
            original.auth.install_secret
        );
        assert_eq!(ready.runtime.load().unwrap(), Some(original.runtime));
        assert!(staging.load().unwrap().is_none());
        let again =
            prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).unwrap();
        assert_eq!(
            again.auth.load().unwrap().unwrap().install_secret,
            original.auth.install_secret
        );
        let journal =
            std::fs::read_to_string(root.path().join("common/runtime-inventory-v1.json")).unwrap();
        assert!(!journal.contains(&original.auth.install_secret));
    }
}

#[test]
fn supported_orphan_namespace_and_corrupt_anchor_are_never_fresh_install() {
    for namespace in [
        "auth-v1",
        "runtime/stable/state/0.2.16/state-v1.json",
        "runtime/latest/state/0.2.16/state-v1.json:pending-write-v1",
    ] {
        let root = tempfile::tempdir().unwrap();
        let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
        let records = Records::default();
        records
            .values
            .lock()
            .unwrap()
            .insert(namespace.into(), b"corrupt synthetic anchor".to_vec());
        assert!(
            prepare_runtime_storage(&lock, &manifest(), RuntimeSlot::Latest, &records).is_err(),
            "{namespace}"
        );
        assert_eq!(records.writes.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn valid_unanchored_other_runtime_blocks_legacy_initialization_too() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let records = Records::default();
    let legacy = StoredAuth::new_install();
    records.legacy.save(&legacy).unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let orphan = ProtectedRuntimeStore::new(records.record(paths.namespace()), paths);
    orphan
        .save(&RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            orphan.paths(),
        ))
        .unwrap();
    let writes = records.writes.load(Ordering::SeqCst);
    assert!(prepare_runtime_storage(&lock, &manifest(), RuntimeSlot::Latest, &records).is_err());
    assert_eq!(records.writes.load(Ordering::SeqCst), writes);
    assert!(ProtectedAuthStore::new(records.record("auth-v1"))
        .load()
        .unwrap()
        .is_none());
}

#[test]
fn committed_fresh_staging_never_rewinds_same_epoch_auth_metadata() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let records = Records::default();
    let manifest = manifest();
    records.fail_at.store(2, Ordering::SeqCst);
    assert!(prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).is_err());
    let path = RuntimePaths::new(
        root.path(),
        RuntimeSlot::Latest,
        &manifest.latest().runtime_version,
    )
    .unwrap();
    let staging = ProtectedTransactionStore::new(
        records.record(&format!("{}:pending-write-v1", path.namespace())),
        path,
    );
    let stale = staging.load().unwrap().unwrap();
    records.fail_at.store(0, Ordering::SeqCst);
    let ready = prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).unwrap();
    // Reproduce a committed marker with an unremoved staging record. The live
    // owner can advance metadata without incrementing its cancellation epoch.
    staging.save(&stale).unwrap();
    let mut advanced = ready.auth.load().unwrap().unwrap();
    advanced.logout_state = LogoutState::LoggedOut;
    assert_eq!(advanced.auth_epoch, stale.auth.auth_epoch);
    ready.auth.save(&advanced).unwrap();
    let reopened =
        prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).unwrap();
    assert_eq!(reopened.auth.load().unwrap(), Some(advanced));
    assert!(staging.load().unwrap().is_none());
}

#[test]
fn committed_fresh_inventory_missing_either_owner_is_recovery_not_new_install() {
    for missing_auth in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
        let records = Records::default();
        let manifest = manifest();
        let ready =
            prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).unwrap();
        let auth = ready.auth.load().unwrap();
        let path = RuntimePaths::new(
            root.path(),
            RuntimeSlot::Latest,
            &manifest.latest().runtime_version,
        )
        .unwrap();
        records.values.lock().unwrap().remove(if missing_auth {
            "auth-v1"
        } else {
            path.namespace()
        });
        let writes = records.writes.load(Ordering::SeqCst);
        assert!(prepare_runtime_storage(&lock, &manifest, RuntimeSlot::Latest, &records).is_err());
        assert_eq!(records.writes.load(Ordering::SeqCst), writes);
        if !missing_auth {
            assert_eq!(ready.auth.load().unwrap(), auth);
        }
    }
}

// A synthetic private-file backend, not the platform keychain/fallback. Child
// exit deliberately bypasses destructors so a new process owns every replay.
struct ProcessRecords {
    directory: std::path::PathBuf,
    legacy: Legacy,
    writes: Arc<AtomicUsize>,
    crash_after: usize,
}
struct ProcessRecord {
    path: std::path::PathBuf,
    writes: Arc<AtomicUsize>,
    crash_after: usize,
}
impl ProcessRecord {
    fn crash_point(&self) {
        let count = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if count == self.crash_after {
            std::process::exit(201);
        }
    }
}
impl ProtectedRecordStore for ProcessRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        use std::io::Write;
        let directory = self.path.parent().unwrap();
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        file.persist(&self.path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(directory)?.sync_all()?;
        self.crash_point();
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        // This point is after the durable commit marker but before removing
        // staging; the next process must recognize the committed residue.
        self.crash_point();
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
impl ProtectedRecordFactory for ProcessRecords {
    type Record = ProcessRecord;
    fn record(&self, namespace: &str) -> Self::Record {
        use sha2::{Digest, Sha256};
        ProcessRecord {
            path: self
                .directory
                .join(format!("{:x}", Sha256::digest(namespace.as_bytes()))),
            writes: self.writes.clone(),
            crash_after: self.crash_after,
        }
    }
    fn legacy(&self) -> &dyn SecretStore {
        &self.legacy
    }
}

#[test]
fn fresh_storage_child_process() {
    let Ok(root) = std::env::var("NELOMAI_SYNTHETIC_FRESH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let records = ProcessRecords {
        directory: root.join("synthetic-records"),
        legacy: Legacy::default(),
        writes: Arc::default(),
        crash_after: std::env::var("NELOMAI_SYNTHETIC_FRESH_CRASH")
            .unwrap()
            .parse()
            .unwrap(),
    };
    let lock = ContainerOwnerLock::try_acquire(&root).unwrap();
    prepare_runtime_storage(&lock, &manifest(), RuntimeSlot::Latest, &records).unwrap();
}

#[test]
fn process_exit_replays_fresh_pair_after_staging_auth_runtime_and_durable_commit() {
    for crash_after in 1..=4 {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("synthetic-records");
        std::fs::create_dir(&directory).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fresh_storage_child_process"])
            .env("NELOMAI_SYNTHETIC_FRESH_ROOT", root.path())
            .env("NELOMAI_SYNTHETIC_FRESH_CRASH", crash_after.to_string())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(201), "crash point {crash_after}");
        let records = ProcessRecords {
            directory,
            legacy: Legacy::default(),
            writes: Arc::default(),
            crash_after: 0,
        };
        let manifest = manifest();
        let path = RuntimePaths::new(
            root.path(),
            RuntimeSlot::Latest,
            &manifest.latest().runtime_version,
        )
        .unwrap();
        let staging = ProtectedTransactionStore::new(
            records.record(&format!("{}:pending-write-v1", path.namespace())),
            path,
        );
        let original = staging.load().unwrap().unwrap();
        // Actual second process replay, not only retrying an in-memory adapter.
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "fresh_storage_child_process"])
            .env("NELOMAI_SYNTHETIC_FRESH_ROOT", root.path())
            .env("NELOMAI_SYNTHETIC_FRESH_CRASH", "0")
            .status()
            .unwrap()
            .success());
        assert_eq!(
            ProtectedAuthStore::new(records.record("auth-v1"))
                .load()
                .unwrap(),
            Some(original.auth)
        );
        assert!(staging.load().unwrap().is_none());
    }
}
