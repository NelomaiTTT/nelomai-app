use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub use nelomai_contracts::{
    Layer as StoredLayer, RouteMode as StoredRouteMode,
    TicConnectionMode as StoredTicConnectionMode,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

const SERVICE_NAME: &str = "ru.nelomai.app";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredConnectionKind {
    Fixed,
    DynamicWarm,
    Pinned,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredConnection {
    pub lease_id: String,
    pub layer: StoredLayer,
    pub tic_connection_mode: StoredTicConnectionMode,
    pub route_mode: StoredRouteMode,
    pub kind: StoredConnectionKind,
    pub configuration: String,
    pub valid_until_unix: Option<i64>,
}

impl fmt::Debug for StoredConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredConnection")
            .field("lease_id", &self.lease_id)
            .field("layer", &self.layer)
            .field("tic_connection_mode", &self.tic_connection_mode)
            .field("route_mode", &self.route_mode)
            .field("kind", &self.kind)
            .field("configuration", &"<redacted>")
            .field("valid_until_unix", &self.valid_until_unix)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCompatibility {
    pub update_required: bool,
    pub observed_at_unix: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAuth {
    pub install_secret: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub saved_connection: Option<StoredConnection>,
    #[serde(default)]
    pub pinned_connection: Option<StoredConnection>,
    #[serde(default)]
    pub compatibility: Option<StoredCompatibility>,
}

impl fmt::Debug for StoredAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredAuth")
            .field("install_secret", &"<redacted>")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("saved_connection", &self.saved_connection)
            .field("pinned_connection", &self.pinned_connection)
            .field("compatibility", &self.compatibility)
            .finish()
    }
}

impl StoredAuth {
    pub fn new_install() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self {
            install_secret: URL_SAFE_NO_PAD.encode(bytes),
            access_token: None,
            refresh_token: None,
            saved_connection: None,
            pinned_connection: None,
            compatibility: None,
        }
    }
}

pub trait SecretStore: Send + Sync {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError>;
    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError>;
    fn delete(&self) -> Result<(), StorageError>;
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("system credential store failed: {0}")]
    Keyring(String),
    #[error("Linux credential store is unavailable and no protected fallback was configured")]
    LinuxFallbackNotConfigured,
    #[error("protected fallback I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("stored credentials are invalid: {0}")]
    InvalidData(#[from] serde_json::Error),
}

pub struct SystemSecretStore {
    account: String,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    linux_fallback_dir: Option<PathBuf>,
}

impl SystemSecretStore {
    pub fn new(account: impl Into<String>, linux_fallback_dir: Option<PathBuf>) -> Self {
        Self {
            account: account.into(),
            linux_fallback_dir,
        }
    }

    fn serialized(auth: &StoredAuth) -> Result<Vec<u8>, StorageError> {
        Ok(serde_json::to_vec(auth)?)
    }

    #[cfg(not(target_os = "android"))]
    fn load_native(&self) -> Result<Option<StoredAuth>, NativeStoreError> {
        let entry =
            keyring::Entry::new(SERVICE_NAME, &self.account).map_err(NativeStoreError::from)?;
        match entry.get_secret() {
            Ok(value) => serde_json::from_slice(&value)
                .map(Some)
                .map_err(StorageError::from)
                .map_err(NativeStoreError::Fatal),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(NativeStoreError::from(error)),
        }
    }

    #[cfg(not(target_os = "android"))]
    fn save_native(&self, auth: &StoredAuth) -> Result<(), NativeStoreError> {
        let entry =
            keyring::Entry::new(SERVICE_NAME, &self.account).map_err(NativeStoreError::from)?;
        entry
            .set_secret(&Self::serialized(auth).map_err(NativeStoreError::Fatal)?)
            .map_err(NativeStoreError::from)
    }

    #[cfg(not(target_os = "android"))]
    fn delete_native(&self) -> Result<(), NativeStoreError> {
        let entry =
            keyring::Entry::new(SERVICE_NAME, &self.account).map_err(NativeStoreError::from)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(NativeStoreError::from(error)),
        }
    }

    #[cfg(target_os = "android")]
    fn android_entry(&self) -> Result<keyring_core::Entry, StorageError> {
        use std::sync::OnceLock;
        static INITIALIZED: OnceLock<Result<(), String>> = OnceLock::new();
        let initialized = INITIALIZED.get_or_init(|| {
            let store =
                android_native_keyring_store::Store::new().map_err(|error| error.to_string())?;
            keyring_core::set_default_store(store);
            Ok(())
        });
        initialized
            .as_ref()
            .map_err(|error| StorageError::Keyring(error.clone()))?;
        keyring_core::Entry::new(SERVICE_NAME, &self.account)
            .map_err(|error| StorageError::Keyring(error.to_string()))
    }

    #[cfg(target_os = "android")]
    fn load_native(&self) -> Result<Option<StoredAuth>, NativeStoreError> {
        let entry = self.android_entry().map_err(NativeStoreError::Fatal)?;
        match entry.get_secret() {
            Ok(value) => serde_json::from_slice(&value)
                .map(Some)
                .map_err(StorageError::from)
                .map_err(NativeStoreError::Fatal),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(NativeStoreError::Fatal(StorageError::Keyring(
                error.to_string(),
            ))),
        }
    }

    #[cfg(target_os = "android")]
    fn save_native(&self, auth: &StoredAuth) -> Result<(), NativeStoreError> {
        self.android_entry()
            .map_err(NativeStoreError::Fatal)?
            .set_secret(&Self::serialized(auth).map_err(NativeStoreError::Fatal)?)
            .map_err(|error| NativeStoreError::Fatal(StorageError::Keyring(error.to_string())))
    }

    #[cfg(target_os = "android")]
    fn delete_native(&self) -> Result<(), NativeStoreError> {
        let entry = self.android_entry().map_err(NativeStoreError::Fatal)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(NativeStoreError::Fatal(StorageError::Keyring(
                error.to_string(),
            ))),
        }
    }

    #[cfg(target_os = "linux")]
    fn fallback(&self) -> Result<ProtectedFileStore, StorageError> {
        self.linux_fallback_dir
            .as_ref()
            .map(|directory| ProtectedFileStore::new(directory, &self.account))
            .ok_or(StorageError::LinuxFallbackNotConfigured)
    }
}

impl SecretStore for SystemSecretStore {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        match self.load_native() {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => {
                #[cfg(target_os = "linux")]
                if let Some(directory) = &self.linux_fallback_dir {
                    let fallback = ProtectedFileStore::new(directory, &self.account);
                    if let Some(value) = fallback.load()? {
                        self.save_native(&value).map_err(|error| match error {
                            NativeStoreError::Unavailable => StorageError::Keyring(
                                "Secret Service became unavailable during migration".to_string(),
                            ),
                            NativeStoreError::Fatal(error) => error,
                        })?;
                        fallback.delete()?;
                        return Ok(Some(value));
                    }
                }
                Ok(None)
            }
            #[cfg(target_os = "linux")]
            Err(NativeStoreError::Unavailable) => self.fallback()?.load(),
            Err(NativeStoreError::Fatal(error)) => Err(error),
        }
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        match self.save_native(auth) {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                if let Some(directory) = &self.linux_fallback_dir {
                    ProtectedFileStore::new(directory, &self.account).delete()?;
                }
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Err(NativeStoreError::Unavailable) => self.fallback()?.save(auth),
            Err(NativeStoreError::Fatal(error)) => Err(error),
        }
    }

    fn delete(&self) -> Result<(), StorageError> {
        match self.delete_native() {
            Ok(()) => {
                #[cfg(target_os = "linux")]
                if let Some(directory) = &self.linux_fallback_dir {
                    ProtectedFileStore::new(directory, &self.account).delete()?;
                }
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Err(NativeStoreError::Unavailable) => self.fallback()?.delete(),
            Err(NativeStoreError::Fatal(error)) => Err(error),
        }
    }
}

enum NativeStoreError {
    #[cfg(target_os = "linux")]
    Unavailable,
    Fatal(StorageError),
}

#[cfg(not(target_os = "android"))]
impl From<keyring::Error> for NativeStoreError {
    fn from(error: keyring::Error) -> Self {
        #[cfg(target_os = "linux")]
        if matches!(
            error,
            keyring::Error::NoDefaultStore | keyring::Error::PlatformFailure(_)
        ) {
            return Self::Unavailable;
        }
        Self::Fatal(StorageError::Keyring(error.to_string()))
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ProtectedFileStore {
    directory: PathBuf,
    path: PathBuf,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl ProtectedFileStore {
    fn new(directory: impl AsRef<Path>, account: &str) -> Self {
        let file_name = format!("{:x}.json", Sha256::digest(account.as_bytes()));
        Self {
            directory: directory.as_ref().to_path_buf(),
            path: directory.as_ref().join(file_name),
        }
    }

    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn save(&self, auth: &StoredAuth) -> Result<(), StorageError> {
        create_protected_dir(&self.directory)?;
        let temporary = self.path.with_extension("tmp");
        write_protected_file(&temporary, &SystemSecretStore::serialized(auth)?)?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn create_protected_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn create_protected_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_protected_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn write_protected_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn install_secret_has_expected_entropy_and_url_safe_shape() {
        let first = StoredAuth::new_install();
        let second = StoredAuth::new_install();
        assert_eq!(first.install_secret.len(), 43);
        assert_ne!(first.install_secret, second.install_secret);
        assert!(first
            .install_secret
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '_' || value == '-'));
    }

    #[test]
    fn legacy_credentials_load_with_empty_connection_state() {
        let legacy = json!({
            "install_secret": "legacy-install-secret",
            "access_token": "access-secret",
            "refresh_token": "refresh-secret"
        });
        let stored: StoredAuth = serde_json::from_value(legacy).unwrap();
        assert!(stored.saved_connection.is_none());
        assert!(stored.pinned_connection.is_none());
        assert!(stored.compatibility.is_none());
    }

    #[test]
    fn debug_output_redacts_every_secret() {
        let mut stored = StoredAuth::new_install();
        stored.access_token = Some("access-secret".to_string());
        stored.refresh_token = Some("refresh-secret".to_string());
        stored.saved_connection = Some(StoredConnection {
            lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
            layer: StoredLayer::Stray,
            tic_connection_mode: StoredTicConnectionMode::Dynamic,
            route_mode: StoredRouteMode::Standalone,
            kind: StoredConnectionKind::Pinned,
            configuration: "PrivateKey = tunnel-secret".to_string(),
            valid_until_unix: None,
        });

        let debug = format!("{stored:?}");
        for secret in [
            &stored.install_secret,
            "access-secret",
            "refresh-secret",
            "tunnel-secret",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn saved_connection_survives_serialization_without_losing_lease_expiry() {
        let mut stored = StoredAuth::new_install();
        stored.saved_connection = Some(StoredConnection {
            lease_id: "11111111-1111-4111-8111-111111111111".to_string(),
            layer: StoredLayer::Stray,
            tic_connection_mode: StoredTicConnectionMode::Dynamic,
            route_mode: StoredRouteMode::Standalone,
            kind: StoredConnectionKind::DynamicWarm,
            configuration: "[Interface]\nPrivateKey = secret\n".to_string(),
            valid_until_unix: Some(1_800_000_000),
        });
        stored.pinned_connection = Some(StoredConnection {
            lease_id: "22222222-2222-4222-8222-222222222222".to_string(),
            layer: StoredLayer::Stray,
            tic_connection_mode: StoredTicConnectionMode::Dynamic,
            route_mode: StoredRouteMode::Standalone,
            kind: StoredConnectionKind::Pinned,
            configuration: "[Interface]\nPrivateKey = pinned-secret\n".to_string(),
            valid_until_unix: None,
        });
        stored.compatibility = Some(StoredCompatibility {
            update_required: false,
            observed_at_unix: 1_700_000_000,
        });

        let round_trip: StoredAuth =
            serde_json::from_slice(&SystemSecretStore::serialized(&stored).unwrap()).unwrap();
        assert_eq!(round_trip, stored);
    }

    #[test]
    fn protected_file_round_trip_uses_private_permissions() {
        let root = std::env::temp_dir().join(format!(
            "nelomai-client-storage-{}",
            StoredAuth::new_install().install_secret
        ));
        let store = ProtectedFileStore::new(&root, "test-account");
        let auth = StoredAuth::new_install();
        store.save(&auth).unwrap();
        assert_eq!(store.load().unwrap(), Some(auth));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&store.path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        store.delete().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
