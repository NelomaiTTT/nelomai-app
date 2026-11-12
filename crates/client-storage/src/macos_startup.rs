//! Select the macOS record authority under the existing Common owner lock.
use super::*;
use crate::macos_vault::{MacosVault, UserKeychain, VaultKeychain};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const ACTIVATION: &str = "vault-activation-v1";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum VaultPhase {
    Staging,
    Active,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VaultAuthority {
    pub(super) installation: Uuid,
    pub(super) phase: VaultPhase,
    pub(super) required_namespaces: BTreeSet<String>,
}

impl VaultAuthority {
    pub(super) fn valid_for(&self, namespaces: &[String]) -> bool {
        match self.phase {
            VaultPhase::Staging => self.required_namespaces.is_empty(),
            VaultPhase::Active => {
                !self.required_namespaces.is_empty()
                    && self
                        .required_namespaces
                        .iter()
                        .all(|name| namespaces.contains(name))
            }
        }
    }
}

#[derive(Clone)]
pub struct MacosRecordFactory(Arc<Backend>);

enum Backend {
    Legacy(SystemRecordFactory),
    Vault {
        installation: Uuid,
        vault: Arc<MacosVault>,
    },
}

pub struct MacosRecord(Record);

enum Record {
    Legacy(SystemSecretStore),
    Vault {
        vault: Arc<MacosVault>,
        namespace: String,
    },
}

impl MacosRecordFactory {
    /// Call only with the verified installed manifest and a pinned Common owner.
    pub fn prepare(
        owner: &Arc<ContainerOwnerLock>,
        manifest: &VerifiedContainerManifest,
        selected: RuntimeSlot,
    ) -> Result<(Self, PreparedRuntimeStorage<MacosRecord>), StorageError> {
        let marker = read_inventory(owner.root())?;
        let exists = MacosVault::has_directory(owner)?;
        let mut staged_vault = None;
        if let Some((inventory, authority)) = marker.as_ref().and_then(|inventory| {
            inventory
                .vault_authority
                .as_ref()
                .map(|authority| (inventory, authority))
        }) {
            if authority.phase == VaultPhase::Active || exists {
                let vault = MacosVault::open(owner.clone(), authority.installation)?;
                if restore_activation(owner, inventory, &vault)? {
                    let factory = Self::vault(authority.installation, vault);
                    let storage = prepare_runtime_storage(owner, manifest, selected, &factory)?;
                    return Ok((factory, storage));
                }
                staged_vault = Some(vault);
            }
        } else if exists {
            return recovery();
        }

        // Pin one User Keychain across legacy validation, the copy and key
        // provisioning. A change to the default must not mix two installations.
        let keychain = UserKeychain::open()?;
        let legacy = Self(Arc::new(Backend::Legacy(SystemRecordFactory {
            legacy: SystemSecretStore::in_user_keychain("primary".into(), keychain.0.clone()),
            account: "primary".into(),
            fallback: None,
        })));
        let storage = prepare_runtime_storage(owner, manifest, selected, &legacy)?;
        if matches!(storage.migration, Some(MigrationOutcome::AwaitingBootstrap)) {
            // The existing migration acknowledgement still needs the legacy
            // identity. The next Common launch can migrate the committed result.
            return Ok((legacy, storage));
        }

        let marker = read_inventory(owner.root())?.ok_or(StorageError::RecoveryRequired(
            "validated inventory missing before vault migration",
        ))?;
        let factory = activate(
            owner,
            marker,
            storage.runtime.paths().namespace(),
            &legacy,
            &keychain,
            staged_vault,
        )?;
        let storage = prepare_runtime_storage(owner, manifest, selected, &factory)?;
        Ok((factory, storage))
    }

    fn vault(installation: Uuid, vault: MacosVault) -> Self {
        Self(Arc::new(Backend::Vault {
            installation,
            vault: Arc::new(vault),
        }))
    }
}

fn activate(
    owner: &Arc<ContainerOwnerLock>,
    mut inventory: Inventory,
    selected: &str,
    source: &impl ProtectedRecordFactory,
    keychain: &impl VaultKeychain,
    staged_vault: Option<MacosVault>,
) -> Result<MacosRecordFactory, StorageError> {
    if !inventory.committed || !inventory.namespaces.iter().any(|name| name == selected) {
        return recovery();
    }
    let installation = match inventory.vault_authority.as_ref() {
        None => {
            let installation = Uuid::new_v4();
            inventory.vault_authority = Some(VaultAuthority {
                installation,
                phase: VaultPhase::Staging,
                required_namespaces: BTreeSet::new(),
            });
            // Publish the fence before writing any vault data. Old Common
            // rejects the extra field. An interrupted migration can only
            // resume from the legacy authority with the same installation ID.
            write_inventory(owner.root(), &inventory)?;
            installation
        }
        Some(authority) if authority.phase == VaultPhase::Staging => authority.installation,
        Some(_) => return recovery(),
    };
    let vault = match staged_vault {
        Some(vault) => vault,
        None => MacosVault::initialize_with_keychain(owner.clone(), installation, keychain)?,
    };
    let auth = load_source(source, "auth-v1")?.ok_or(StorageError::RecoveryRequired(
        "vault migration auth record missing",
    ))?;
    let anchor: AuthStoreV1 = decode_record(&auth, "auth-v1")?;
    anchor.validate()?;
    if digest(&anchor.install_secret)? != inventory.install_sha256 {
        return recovery();
    }
    copy_record(&vault, "auth-v1", Some(auth.as_slice()))?;
    let factory = MacosRecordFactory::vault(installation, vault);
    let Backend::Vault { vault, .. } = factory.0.as_ref() else {
        unreachable!("constructed vault factory")
    };
    let mut required_namespaces = BTreeSet::new();
    for namespace in &inventory.namespaces {
        let paths = paths_from_namespace(owner.root(), namespace)?;
        let record = load_source(source, namespace)?;
        if record.is_some() {
            required_namespaces.insert(namespace.clone());
        }
        copy_record(vault, namespace, record.as_deref().map(Vec::as_slice))?;
        ProtectedRuntimeStore::new(factory.record(namespace), paths.clone()).load()?;
        let pending = format!("{namespace}:pending-write-v1");
        let record = load_source(source, &pending)?;
        copy_record(vault, &pending, record.as_deref().map(Vec::as_slice))?;
        ProtectedTransactionStore::new(factory.record(&pending), paths).load()?;
    }
    if !required_namespaces.contains(selected) {
        return recovery();
    }
    inventory.vault_authority = Some(VaultAuthority {
        installation,
        phase: VaultPhase::Active,
        required_namespaces,
    });
    // The seal is durable before the active marker. A crash between the
    // writes must resume the already verified copy, never replay legacy data.
    let bytes = encode_record(&inventory, ACTIVATION)?;
    copy_record(vault, ACTIVATION, Some(&bytes))?;
    restore_activation(owner, &inventory, vault)?;
    write_inventory(owner.root(), &inventory)?;
    Ok(factory)
}

fn restore_activation(
    owner: &ContainerOwnerLock,
    inventory: &Inventory,
    vault: &MacosVault,
) -> Result<bool, StorageError> {
    let authority = inventory
        .vault_authority
        .as_ref()
        .ok_or(StorageError::RecoveryRequired(
            "vault inventory has no authority",
        ))?;
    let Some(bytes) = vault.read(ACTIVATION)? else {
        return if authority.phase == VaultPhase::Staging {
            Ok(false)
        } else {
            recovery()
        };
    };
    let sealed: Inventory = decode_record(bytes.as_ref(), ACTIVATION)?;
    let sealed_authority =
        sealed
            .vault_authority
            .as_ref()
            .ok_or(StorageError::RecoveryRequired(
                "vault activation has no authority",
            ))?;
    if sealed.schema_version != inventory.schema_version
        || !sealed.committed
        || sealed.install_sha256 != inventory.install_sha256
        || sealed.fresh_transaction_id != inventory.fresh_transaction_id
        || sealed_authority.installation != authority.installation
        || sealed_authority.phase != VaultPhase::Active
        || !sealed_authority.valid_for(&sealed.namespaces)
        || !sealed
            .namespaces
            .iter()
            .all(|name| inventory.namespaces.contains(name))
    {
        return recovery();
    }
    if authority.phase == VaultPhase::Staging {
        write_inventory(owner.root(), &sealed)?;
    } else if !sealed_authority
        .required_namespaces
        .is_subset(&authority.required_namespaces)
    {
        return recovery();
    }
    Ok(true)
}

fn load_source(
    source: &impl ProtectedRecordFactory,
    namespace: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
    Ok(source.record(namespace).load_record()?.map(Zeroizing::new))
}

fn copy_record(
    vault: &MacosVault,
    namespace: &str,
    source: Option<&[u8]>,
) -> Result<(), StorageError> {
    if vault.read(namespace)?.as_ref().map(AsRef::as_ref) != source {
        match source {
            Some(bytes) => vault.write(namespace, bytes)?,
            None => vault.delete(namespace)?,
        }
    }
    if vault.read(namespace)?.as_ref().map(AsRef::as_ref) != source {
        return recovery();
    }
    Ok(())
}

impl ProtectedRecordFactory for MacosRecordFactory {
    type Record = MacosRecord;

    fn record(&self, namespace: &str) -> Self::Record {
        MacosRecord(match self.0.as_ref() {
            Backend::Legacy(factory) => Record::Legacy(factory.record(namespace)),
            Backend::Vault { vault, .. } => Record::Vault {
                vault: vault.clone(),
                namespace: namespace.to_owned(),
            },
        })
    }

    fn legacy(&self) -> &dyn SecretStore {
        match self.0.as_ref() {
            Backend::Legacy(factory) => factory.legacy(),
            Backend::Vault { .. } => &InactiveLegacy,
        }
    }

    fn active_macos_vault(&self) -> Option<Uuid> {
        match self.0.as_ref() {
            Backend::Legacy(_) => None,
            Backend::Vault { installation, .. } => Some(*installation),
        }
    }
}

impl ProtectedRecordStore for MacosRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match &self.0 {
            Record::Legacy(record) => record.load_record(),
            Record::Vault { vault, namespace } => {
                Ok(vault.read(namespace)?.map(|bytes| bytes.as_ref().to_vec()))
            }
        }
    }

    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        match &self.0 {
            Record::Legacy(record) => record.save_record(bytes),
            Record::Vault { vault, namespace } => vault.write(namespace, bytes),
        }
    }

    fn delete_record(&self) -> Result<(), StorageError> {
        match &self.0 {
            Record::Legacy(record) => record.delete_record(),
            Record::Vault { vault, namespace } => vault.delete(namespace),
        }
    }
}

struct InactiveLegacy;

impl SecretStore for InactiveLegacy {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        recovery()
    }
    fn save(&self, _: &StoredAuth) -> Result<(), StorageError> {
        recovery()
    }
    fn delete(&self) -> Result<(), StorageError> {
        recovery()
    }
}

#[cfg(test)]
#[path = "macos_startup_tests.rs"]
mod tests;
