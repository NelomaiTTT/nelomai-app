//! Standalone macOS record vault. Startup must decide migration authority
//! before exposing it to the auth broker or the runtime storage endpoint.
use crate::{ContainerOwnerLock, StorageError, SERVICE_NAME};
#[path = "macos_vault_fs.rs"]
mod filesystem;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use filesystem::{
    check_common, check_directory, create_vault, open_private_directory, open_record,
    recover_directory, remove_record, write_record,
};
use rand::{rngs::OsRng, TryRngCore};
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use security_framework_sys::base::errSecItemNotFound;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    sync::Arc,
};
use uuid::Uuid;
use zeroize::Zeroizing;

const DIRECTORY: &str = "vault-v1";
const BINDING: &str = "binding";
const BINDING_NAMESPACE: &str = "";
const MAGIC: &[u8] = b"NELOMAI-VAULT\x01";
const NONCE_LEN: usize = 24;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FILE_BYTES: usize = MAGIC.len() + NONCE_LEN + MAX_RECORD_BYTES + 16;

pub(crate) type VaultKey = Zeroizing<[u8; 32]>;

pub(crate) trait VaultKeychain {
    fn load(&self, installation: Uuid) -> Result<Option<VaultKey>, StorageError>;
    fn add(&self, installation: Uuid, key: &[u8; 32]) -> Result<(), StorageError>;
}

pub(crate) struct UserKeychain(pub(crate) SecKeychain);

impl UserKeychain {
    pub(crate) fn open() -> Result<Self, StorageError> {
        SecKeychain::default_for_domain(SecPreferencesDomain::User)
            .map(Self)
            .map_err(|_| StorageError::RecoveryRequired("user Keychain unavailable"))
    }

    fn account(installation: Uuid) -> String {
        format!("primary:vault-key-v1:{installation}")
    }
}

impl VaultKeychain for UserKeychain {
    fn load(&self, installation: Uuid) -> Result<Option<VaultKey>, StorageError> {
        match self
            .0
            .find_generic_password(SERVICE_NAME, &Self::account(installation))
        {
            Ok((password, _)) => {
                let mut key = VaultKey::new([0; 32]);
                if password.len() != key.len() {
                    return Err(StorageError::RecoveryRequired("invalid vault key length"));
                }
                key.copy_from_slice(&password);
                Ok(Some(key))
            }
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(_) => Err(StorageError::RecoveryRequired("vault key unavailable")),
        }
    }

    fn add(&self, installation: Uuid, key: &[u8; 32]) -> Result<(), StorageError> {
        self.0
            .add_generic_password(SERVICE_NAME, &Self::account(installation), key)
            .map_err(|_| StorageError::RecoveryRequired("vault key could not be added"))
    }
}

/// Decrypted bytes are cleared on drop and have no diagnostic representation.
pub struct VaultRecord(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for VaultRecord {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// An encrypted file backend with one user Keychain item per installation.
/// Keep this instance with Common so record operations reuse the opened key.
/// Acquire its owner with [`ContainerOwnerLock::try_acquire_for_macos_vault`].
pub struct MacosVault {
    owner: Arc<ContainerOwnerLock>,
    directory: File,
    installation: Uuid,
    cipher: XChaCha20Poly1305,
}

impl MacosVault {
    /// Open only a committed vault. A missing directory or key is an error.
    pub fn open(owner: Arc<ContainerOwnerLock>, installation: Uuid) -> Result<Self, StorageError> {
        Self::open_with_keychain(owner, installation, &UserKeychain::open()?)
    }

    /// Provision during a proven fresh install or an explicitly staged
    /// migration. Callers must use `open` after activating the vault.
    pub fn initialize(
        owner: Arc<ContainerOwnerLock>,
        installation: Uuid,
    ) -> Result<Self, StorageError> {
        Self::initialize_with_keychain(owner, installation, &UserKeychain::open()?)
    }

    pub(crate) fn open_with_keychain(
        owner: Arc<ContainerOwnerLock>,
        installation: Uuid,
        keychain: &impl VaultKeychain,
    ) -> Result<Self, StorageError> {
        validate_installation(installation)?;
        let _gate = owner.lock_vault()?;
        check_common(&owner)?;
        let directory = open_private_directory(&owner.vault_directories()?.common, DIRECTORY)?;
        Self::open_existing(owner.clone(), directory, installation, keychain)
    }

    fn open_existing(
        owner: Arc<ContainerOwnerLock>,
        directory: File,
        installation: Uuid,
        keychain: &impl VaultKeychain,
    ) -> Result<Self, StorageError> {
        let key = keychain
            .load(installation)?
            .ok_or(StorageError::RecoveryRequired("existing vault has no key"))?;
        let vault = Self {
            owner,
            directory,
            installation,
            cipher: XChaCha20Poly1305::new((&*key).into()),
        };
        vault.finish_open()
    }

    pub(crate) fn initialize_with_keychain(
        owner: Arc<ContainerOwnerLock>,
        installation: Uuid,
        keychain: &impl VaultKeychain,
    ) -> Result<Self, StorageError> {
        validate_installation(installation)?;
        let _gate = owner.lock_vault()?;
        check_common(&owner)?;
        match open_private_directory(&owner.vault_directories()?.common, DIRECTORY) {
            Ok(dir) => return Self::open_existing(owner.clone(), dir, installation, keychain),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let key = match keychain.load(installation)? {
            Some(key) => key,
            None => {
                check_common(&owner)?;
                let mut key = VaultKey::new([0; 32]);
                fill_random(&mut *key)?;
                keychain.add(installation, &key)?;
                key
            }
        };
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let binding = seal(&cipher, installation, BINDING_NAMESPACE, &[])?;
        let directory = create_vault(&owner, DIRECTORY, (BINDING, &binding))?;
        let vault = Self {
            owner: owner.clone(),
            directory,
            installation,
            cipher,
        };
        vault.finish_open()
    }

    fn finish_open(self) -> Result<Self, StorageError> {
        self.check_live()?;
        recover_directory(&self.owner, &self.directory, BINDING)?;
        self.check_live()?;
        Ok(self)
    }

    pub fn read(&self, namespace: &str) -> Result<Option<VaultRecord>, StorageError> {
        let name = record_name(namespace)?;
        self.check_live()?;
        let record = self.read_record(&name, namespace)?;
        self.check_location()?;
        Ok(record)
    }

    pub fn write(&self, namespace: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let name = record_name(namespace)?;
        let _gate = self.owner.lock_vault()?;
        self.check_live()?;
        // Preserve an invalid record for recovery rather than overwriting it.
        self.read_record(&name, namespace)?;
        let sealed = seal(&self.cipher, self.installation, namespace, bytes)?;
        write_record(&self.directory, &name, &sealed)?;
        self.check_live()
    }

    pub(crate) fn delete(&self, namespace: &str) -> Result<(), StorageError> {
        let name = record_name(namespace)?;
        let _gate = self.owner.lock_vault()?;
        self.check_live()?;
        if self.read_record(&name, namespace)?.is_some() {
            remove_record(&self.directory, &name)?;
        }
        self.check_live()
    }

    /// A vault directory without a matching inventory cannot select legacy storage.
    pub(crate) fn has_directory(owner: &ContainerOwnerLock) -> Result<bool, StorageError> {
        let _gate = owner.lock_vault()?;
        check_common(owner)?;
        match open_private_directory(&owner.vault_directories()?.common, DIRECTORY) {
            Ok(_) => Ok(true),
            Err(StorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn check_location(&self) -> Result<(), StorageError> {
        check_common(&self.owner)?;
        check_directory(
            &self.owner.vault_directories()?.common,
            DIRECTORY,
            &self.directory,
        )
    }

    fn check_live(&self) -> Result<(), StorageError> {
        self.check_location()?;
        match self.read_record(BINDING, BINDING_NAMESPACE)? {
            Some(binding) if binding.as_ref().is_empty() => Ok(()),
            _ => Err(StorageError::RecoveryRequired("vault binding unavailable")),
        }
    }

    fn read_record(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<VaultRecord>, StorageError> {
        let Some(file) = open_record(&self.directory, name)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        let limit = if namespace == BINDING_NAMESPACE {
            MAX_FILE_BYTES - MAX_RECORD_BYTES
        } else {
            MAX_FILE_BYTES
        };
        file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(StorageError::RecoveryRequired("vault record too large"));
        }
        let (nonce, ciphertext) = bytes
            .strip_prefix(MAGIC)
            .and_then(|envelope| envelope.split_at_checked(NONCE_LEN))
            .ok_or(StorageError::RecoveryRequired(
                "invalid vault record format",
            ))?;
        let plain = self
            .cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad(self.installation, namespace),
                },
            )
            .map_err(|_| StorageError::RecoveryRequired("vault record authentication failed"))?;
        Ok(Some(VaultRecord(Zeroizing::new(plain))))
    }
}

fn fill_random(bytes: &mut [u8]) -> Result<(), StorageError> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|_| StorageError::RecoveryRequired("secure randomness unavailable"))
}

fn validate_installation(installation: Uuid) -> Result<(), StorageError> {
    if installation.is_nil() {
        return Err(StorageError::RecoveryRequired(
            "invalid vault installation identity",
        ));
    }
    Ok(())
}

fn record_name(namespace: &str) -> Result<String, StorageError> {
    if namespace.is_empty() || namespace.len() > 512 {
        return Err(StorageError::RecoveryRequired("invalid vault namespace"));
    }
    Ok(format!("{:x}.record", Sha256::digest(namespace.as_bytes())))
}

fn aad(installation: Uuid, namespace: &str) -> Vec<u8> {
    [MAGIC, installation.as_bytes(), namespace.as_bytes()].concat()
}

fn seal(
    cipher: &XChaCha20Poly1305,
    installation: Uuid,
    namespace: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, StorageError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StorageError::RecoveryRequired("vault record too large"));
    }
    let mut nonce = XNonce::default();
    fill_random(&mut nonce)?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: bytes,
                aad: &aad(installation, namespace),
            },
        )
        .map_err(|_| StorageError::RecoveryRequired("vault encryption failed"))?;
    Ok([MAGIC, &nonce, &ciphertext].concat())
}

#[cfg(test)]
#[path = "macos_vault_tests.rs"]
mod tests;
