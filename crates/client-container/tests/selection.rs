use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_container::{InstalledRuntimeSelection, SelectionRecovery, SlotSelectionV1};
use nelomai_client_storage::{
    ContainerOwnerLock, ProtectedRecordFactory, ProtectedRecordStore, SecretStore, StorageError,
    StoredAuth,
};
use nelomai_contracts::{
    ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole, RuntimeFileV1, RuntimeSlot,
    RuntimeSlotManifestV1, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
struct Records {
    values: Arc<Mutex<HashMap<String, Vec<u8>>>>,
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
        panic!("selection startup must not delete the legacy store")
    }
}

struct Record {
    key: String,
    records: Records,
}

impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.records.values.lock().unwrap().get(&self.key).cloned())
    }

    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        self.records
            .values
            .lock()
            .unwrap()
            .insert(self.key.clone(), bytes.to_vec());
        Ok(())
    }

    fn delete_record(&self) -> Result<(), StorageError> {
        self.records.values.lock().unwrap().remove(&self.key);
        Ok(())
    }
}

impl ProtectedRecordFactory for Records {
    type Record = Record;

    fn record(&self, namespace: &str) -> Self::Record {
        Record {
            key: namespace.to_owned(),
            records: self.clone(),
        }
    }

    fn legacy(&self) -> &dyn SecretStore {
        &self.legacy
    }
}

fn artifact(version: &str, slot: RuntimeSlot) -> RuntimeSlotManifestV1 {
    RuntimeSlotManifestV1 {
        slot,
        manifest: RuntimeArtifactManifestV1 {
            format_version: 1,
            runtime_version: version.to_owned(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            platform: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
            contract_version: 1,
            files: vec![RuntimeFileV1 {
                path: "bin/nelomai-runtime".to_owned(),
                size_bytes: 17,
                sha256: "a".repeat(64),
                role: RuntimeFileRole::Executable,
            }],
        },
    }
}

fn install_manifest(resources: &std::path::Path, version: &str, stable: bool) -> [u8; 32] {
    std::fs::create_dir_all(resources).unwrap();
    let mut slots = vec![artifact(version, RuntimeSlot::Latest)];
    let (stable_release_set_sha256, stable_platform_manifest_sha256) = if stable {
        slots.push(artifact("0.2.15", RuntimeSlot::Stable));
        (Some("b".repeat(64)), Some("c".repeat(64)))
    } else {
        (None, None)
    };
    let manifest = ContainerManifestV1 {
        format_version: 1,
        container_version: version.to_owned(),
        release_set_id: format!("runtime-{version}"),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256,
        stable_platform_manifest_sha256,
        slots,
    };
    let bytes = serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[41; 32]);
    let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    std::fs::write(resources.join("container-manifest-v1.json"), bytes).unwrap();
    std::fs::write(
        resources.join("container-manifest-v1.sig"),
        key.sign(&signed).to_bytes(),
    )
    .unwrap();
    key.verifying_key().to_bytes()
}

fn selection_path(root: &std::path::Path) -> std::path::PathBuf {
    root.join("common/runtime-selection-v1.json")
}

#[test]
fn first_start_persists_latest_only_after_real_storage_startup_succeeds() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(prepared.storage_slot(), RuntimeSlot::Latest);
    assert!(prepared.requires_storage_confirmation());
    assert!(!selection_path(app_data.path()).exists());

    let (selection, _storage) = prepared.prepare_runtime_storage(&lock, &records).unwrap();
    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(selection.state().pending_slot, None);
    assert_eq!(selection.state().container_version, "0.2.16");
    assert_eq!(selection.recovery(), None);

    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(selection_path(app_data.path())).unwrap()).unwrap();
    assert_eq!(persisted["schema_version"], 1);
    assert_eq!(persisted["container_version"], "0.2.16");
    assert_eq!(persisted["selected_slot"], "latest");
    assert!(persisted["pending_slot"].is_null());
    assert!(!app_data.path().join("runtime-selection-v1.json").exists());
}

#[test]
fn missing_selection_is_not_created_when_protected_inventory_is_corrupt() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();
    records
        .values
        .lock()
        .unwrap()
        .insert("auth-v1".to_owned(), b"orphan-corrupt-record".to_vec());

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert!(prepared.prepare_runtime_storage(&lock, &records).is_err());
    assert!(!selection_path(app_data.path()).exists());
    assert_eq!(
        records.values.lock().unwrap().get("auth-v1").unwrap(),
        b"orphan-corrupt-record"
    );
}

#[test]
fn retry_after_selection_persist_failure_reuses_the_committed_install_identity() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let records = Records::default();
    let path = selection_path(app_data.path());
    let journal_path = app_data.path().join("common/runtime-switch-v1.json");
    let unfinished = br#"{"unfinished":"survives-finalize-retry"}"#;
    std::fs::write(&journal_path, unfinished).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(prepared.prepare_runtime_storage(&lock, &records).is_err());
    let committed_auth = records
        .values
        .lock()
        .unwrap()
        .get("auth-v1")
        .cloned()
        .expect("protected startup committed auth before selection persistence");
    assert_eq!(std::fs::read(&journal_path).unwrap(), unfinished);

    std::fs::remove_dir(&path).unwrap();
    let retry =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert!(retry.requires_storage_confirmation());
    let (selection, _storage) = retry.prepare_runtime_storage(&lock, &records).unwrap();

    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(
        records.values.lock().unwrap().get("auth-v1").unwrap(),
        &committed_auth
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), unfinished);
    assert!(path.is_file());
}

#[test]
fn bad_manifest_never_creates_or_defaults_selection() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    std::fs::write(resources.path().join("container-manifest-v1.sig"), [0; 64]).unwrap();

    assert!(InstalledRuntimeSelection::prepare(
        resources.path(),
        &lock,
        Some(&key),
        "linux",
        "x86_64"
    )
    .is_err());
    assert!(!selection_path(app_data.path()).exists());
}

#[test]
fn container_reset_clears_pending_preference_but_preserves_unfinished_journal() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.2.16", false);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let path = selection_path(app_data.path());
    let old = SlotSelectionV1 {
        container_version: "0.2.15".to_owned(),
        selected_slot: RuntimeSlot::Stable,
        pending_slot: Some(RuntimeSlot::Latest),
    };
    std::fs::write(&path, old.to_persisted_bytes().unwrap()).unwrap();
    let journal_path = app_data.path().join("common/runtime-switch-v1.json");
    let unfinished = br#"{"unfinished":"must-survive-selection-reset"}"#;
    std::fs::write(&journal_path, unfinished).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(
        prepared.recovery(),
        Some(&SelectionRecovery::ContainerVersionChanged)
    );
    let (selection, _storage) = prepared
        .prepare_runtime_storage(&lock, &Records::default())
        .unwrap();
    assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
    assert_eq!(selection.state().pending_slot, None);
    assert_eq!(std::fs::read(journal_path).unwrap(), unfinished);
}

#[test]
fn unavailable_stable_and_corrupt_selection_recover_to_latest_with_typed_notice() {
    for (stored, expected) in [
        (
            SlotSelectionV1 {
                container_version: "0.2.16".to_owned(),
                selected_slot: RuntimeSlot::Stable,
                pending_slot: None,
            }
            .to_persisted_bytes()
            .unwrap(),
            SelectionRecovery::UnavailableSlot(RuntimeSlot::Stable),
        ),
        (b"not-json".to_vec(), SelectionRecovery::InvalidSelection),
    ] {
        let app_data = tempfile::tempdir().unwrap();
        let resources = tempfile::tempdir().unwrap();
        let key = install_manifest(resources.path(), "0.2.16", false);
        let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
        std::fs::write(selection_path(app_data.path()), stored).unwrap();

        let prepared = InstalledRuntimeSelection::prepare(
            resources.path(),
            &lock,
            Some(&key),
            "linux",
            "x86_64",
        )
        .unwrap();
        assert_eq!(prepared.recovery(), Some(&expected));
        let (selection, _storage) = prepared
            .prepare_runtime_storage(&lock, &Records::default())
            .unwrap();
        assert_eq!(selection.state().selected_slot, RuntimeSlot::Latest);
        assert_eq!(selection.state().pending_slot, None);
    }
}

#[test]
fn ordinary_runtime_restart_preserves_a_valid_stable_choice() {
    let app_data = tempfile::tempdir().unwrap();
    let resources = tempfile::tempdir().unwrap();
    let key = install_manifest(resources.path(), "0.3.0", true);
    let lock = ContainerOwnerLock::try_acquire(app_data.path()).unwrap();
    let state = SlotSelectionV1 {
        container_version: "0.3.0".to_owned(),
        selected_slot: RuntimeSlot::Stable,
        pending_slot: None,
    };
    let path = selection_path(app_data.path());
    std::fs::write(&path, state.to_persisted_bytes().unwrap()).unwrap();

    let prepared =
        InstalledRuntimeSelection::prepare(resources.path(), &lock, Some(&key), "linux", "x86_64")
            .unwrap();
    assert_eq!(prepared.storage_slot(), RuntimeSlot::Stable);
    assert_eq!(prepared.recovery(), None);
    let (selection, _storage) = prepared
        .prepare_runtime_storage(&lock, &Records::default())
        .unwrap();
    assert_eq!(selection.target().runtime_slot, RuntimeSlot::Stable);
    assert_eq!(
        std::fs::read(path).unwrap(),
        state.to_persisted_bytes().unwrap()
    );
}
