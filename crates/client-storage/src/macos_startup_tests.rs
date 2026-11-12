use super::*;
use crate::macos_vault::VaultKey;
use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::{verify_container_manifest, CONTAINER_MANIFEST_SIGNATURE_DOMAIN};
use std::{collections::HashMap, sync::Mutex};

#[derive(Clone, Default)]
struct MemoryRecords(Arc<Mutex<HashMap<String, Vec<u8>>>>);

struct MemoryRecord(MemoryRecords, String);

impl ProtectedRecordStore for MemoryRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0 .0.lock().unwrap().get(&self.1).cloned())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        self.0
             .0
            .lock()
            .unwrap()
            .insert(self.1.clone(), bytes.to_vec());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        self.0 .0.lock().unwrap().remove(&self.1);
        Ok(())
    }
}

struct EmptyLegacy;
impl SecretStore for EmptyLegacy {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(None)
    }
    fn save(&self, _: &StoredAuth) -> Result<(), StorageError> {
        panic!("startup must not modify the legacy identity")
    }
    fn delete(&self) -> Result<(), StorageError> {
        panic!("startup must not remove the legacy identity")
    }
}

impl ProtectedRecordFactory for MemoryRecords {
    type Record = MemoryRecord;
    fn record(&self, namespace: &str) -> Self::Record {
        MemoryRecord(self.clone(), namespace.to_owned())
    }
    fn legacy(&self) -> &dyn SecretStore {
        &EmptyLegacy
    }
}

#[derive(Default)]
struct TestKeychain {
    key: Mutex<Option<(Uuid, [u8; 32])>>,
    fail_add: std::sync::atomic::AtomicBool,
}

impl VaultKeychain for TestKeychain {
    fn load(&self, installation: Uuid) -> Result<Option<VaultKey>, StorageError> {
        Ok(self
            .key
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(id, _)| *id == installation)
            .map(|(_, key)| VaultKey::new(*key)))
    }
    fn add(&self, installation: Uuid, key: &[u8; 32]) -> Result<(), StorageError> {
        if self.fail_add.load(std::sync::atomic::Ordering::Relaxed) {
            return recovery();
        }
        let mut stored = self.key.lock().unwrap();
        assert!(stored.is_none(), "test key must not be replaced");
        *stored = Some((installation, *key));
        Ok(())
    }
}

fn manifest() -> VerifiedContainerManifest {
    let mut doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/runtime/container-manifest-v1.json"
    ))
    .unwrap();
    doc["container_version"] = "0.4.3".into();
    doc["release_set_id"] = "macos-vault-integration-test".into();
    doc["stable_release_set_sha256"] = "b".repeat(64).into();
    doc["stable_platform_manifest_sha256"] = "c".repeat(64).into();
    doc["slots"][0]["manifest"]["platform"] = "macos".into();
    doc["slots"][0]["manifest"]["architecture"] = "aarch64".into();
    doc["slots"][0]["manifest"]["runtime_version"] = "0.4.3".into();
    let mut stable = doc["slots"][0].clone();
    stable["slot"] = "stable".into();
    stable["manifest"]["runtime_version"] = "0.3.11".into();
    doc["slots"].as_array_mut().unwrap().push(stable);
    let bytes = serde_json::to_vec(&doc).unwrap();
    let signing = SigningKey::from_bytes(&[83; 32]);
    let signed = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &bytes].concat();
    verify_container_manifest(
        &bytes,
        &signing.sign(&signed).to_bytes(),
        &signing.verifying_key().to_bytes(),
        "macos",
        "aarch64",
    )
    .unwrap()
}

fn owner() -> (tempfile::TempDir, Arc<ContainerOwnerLock>) {
    let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire_for_macos_vault(root.path()).unwrap());
    (root, owner)
}

fn inventory(owner: &ContainerOwnerLock) -> Inventory {
    read_inventory(owner.root()).unwrap().unwrap()
}

#[test]
fn one_vault_keeps_both_runtime_slots_and_refuses_legacy_or_missing_state() {
    let (_root, owner) = owner();
    let manifest = manifest();
    let legacy = MemoryRecords::default();
    let latest = prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &legacy).unwrap();
    let namespace = latest.runtime.paths().namespace().to_owned();
    let auth_bytes = legacy.record("auth-v1").load_record().unwrap();
    let runtime_bytes = legacy.record(&namespace).load_record().unwrap();
    let keys = TestKeychain::default();
    let records = activate(&owner, inventory(&owner), &namespace, &legacy, &keys, None).unwrap();
    assert_eq!(records.record("auth-v1").load_record().unwrap(), auth_bytes);
    assert_eq!(
        records.record(&namespace).load_record().unwrap(),
        runtime_bytes
    );
    assert!(prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &legacy).is_err());

    let stable = prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Stable, &records).unwrap();
    let stable_namespace = stable.runtime.paths().namespace().to_owned();
    assert!(records
        .record(&stable_namespace)
        .load_record()
        .unwrap()
        .is_some());
    assert!(legacy
        .record(&stable_namespace)
        .load_record()
        .unwrap()
        .is_none());
    let id = records.active_macos_vault().unwrap();
    let vault = MacosVault::open_with_keychain(owner.clone(), id, &keys).unwrap();
    assert!(restore_activation(&owner, &inventory(&owner), &vault).unwrap());
    let reopened = MacosRecordFactory::vault(id, vault);
    let latest =
        prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &reopened).unwrap();
    assert_eq!(latest.retained[0].paths().namespace(), stable_namespace);
    reopened.record(&stable_namespace).delete_record().unwrap();
    assert!(prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &reopened).is_err());
    assert_eq!(legacy.record("auth-v1").load_record().unwrap(), auth_bytes);
}

#[test]
fn interrupted_staging_keeps_identity_and_sealed_activation_can_finish_without_legacy() {
    use std::sync::atomic::Ordering;
    let (_root, owner) = owner();
    let manifest = manifest();
    let legacy = MemoryRecords::default();
    let latest = prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &legacy).unwrap();
    let namespace = latest.runtime.paths().namespace().to_owned();
    let keys = TestKeychain::default();
    keys.fail_add.store(true, Ordering::Relaxed);
    assert!(activate(&owner, inventory(&owner), &namespace, &legacy, &keys, None).is_err());
    let staged = inventory(&owner);
    let id = staged.vault_authority.as_ref().unwrap().installation;
    assert!(staged.vault_authority.as_ref().unwrap().phase == VaultPhase::Staging);

    keys.fail_add.store(false, Ordering::Relaxed);
    let records = activate(&owner, staged.clone(), &namespace, &legacy, &keys, None).unwrap();
    assert_eq!(records.active_macos_vault(), Some(id));
    // Model the disk boundary after the authenticated seal is flushed and
    // before the active inventory has been published.
    write_inventory(owner.root(), &staged).unwrap();
    legacy.record("auth-v1").delete_record().unwrap();
    let vault = MacosVault::open_with_keychain(owner.clone(), id, &keys).unwrap();
    assert!(restore_activation(&owner, &staged, &vault).unwrap());
    let reopened = MacosRecordFactory::vault(id, vault);
    assert!(prepare_runtime_storage(&owner, &manifest, RuntimeSlot::Latest, &reopened).is_ok());
    keys.key.lock().unwrap().take();
    assert!(MacosVault::open_with_keychain(owner.clone(), id, &keys).is_err());
}
