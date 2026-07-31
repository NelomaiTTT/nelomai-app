use crate::{create_protected_dir, StorageError};
use nelomai_contracts::{SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelPolicy};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const STATE_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_PENDING_APPLY_RESULTS: usize = 32;
const MAX_DOMAIN_RESOLUTIONS: usize = 512;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSplitTunnelDomainResolution {
    pub domain: String,
    pub ipv4_cidrs: Vec<String>,
    pub resolved_at_unix: i64,
}

impl fmt::Debug for StoredSplitTunnelDomainResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSplitTunnelDomainResolution")
            .field("domain_present", &!self.domain.is_empty())
            .field("ipv4_cidrs_count", &self.ipv4_cidrs.len())
            .field("resolved_at_unix", &self.resolved_at_unix)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StoredSplitTunnelState {
    pub cached_policy: Option<SplitTunnelPolicy>,
    pub working_policy_hash: Option<String>,
    pub previous_working_policy: Option<SplitTunnelPolicy>,
    pub applied_physical_network_fingerprint: Option<String>,
    pub last_full_sync_unix: Option<i64>,
    pub last_revision_check_unix: Option<i64>,
    pub last_seen_force_revision: i64,
    pub last_seen_address_revision: i64,
    pub failed_policy_hash: Option<String>,
    pub failed_policy_retry_after_unix: Option<i64>,
    pub pending_apply_results: Vec<SplitTunnelApplyResult>,
    pub domain_resolutions: Vec<StoredSplitTunnelDomainResolution>,
}

impl fmt::Debug for StoredSplitTunnelState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredSplitTunnelState")
            .field(
                "cached_policy_revision",
                &self.cached_policy.as_ref().map(|policy| policy.revision),
            )
            .field("working_policy_hash", &self.working_policy_hash)
            .field(
                "previous_working_policy_revision",
                &self
                    .previous_working_policy
                    .as_ref()
                    .map(|policy| policy.revision),
            )
            .field(
                "applied_physical_network_fingerprint_present",
                &self.applied_physical_network_fingerprint.is_some(),
            )
            .field("last_full_sync_unix", &self.last_full_sync_unix)
            .field("last_revision_check_unix", &self.last_revision_check_unix)
            .field("last_seen_force_revision", &self.last_seen_force_revision)
            .field(
                "last_seen_address_revision",
                &self.last_seen_address_revision,
            )
            .field(
                "failed_policy_hash_present",
                &self.failed_policy_hash.is_some(),
            )
            .field(
                "failed_policy_retry_after_unix",
                &self.failed_policy_retry_after_unix,
            )
            .field(
                "pending_apply_results_count",
                &self.pending_apply_results.len(),
            )
            .field("domain_resolutions_count", &self.domain_resolutions.len())
            .finish()
    }
}

impl StoredSplitTunnelState {
    fn normalized(mut self) -> Self {
        while self.pending_apply_results.len() > MAX_PENDING_APPLY_RESULTS {
            let remove_at = self
                .pending_apply_results
                .iter()
                .position(|result| result.status == SplitTunnelApplyStatus::Applied)
                .unwrap_or(0);
            self.pending_apply_results.remove(remove_at);
        }
        self.domain_resolutions
            .sort_by(|first, second| first.domain.cmp(&second.domain));
        self.domain_resolutions
            .dedup_by(|first, second| first.domain == second.domain);
        self.domain_resolutions.truncate(MAX_DOMAIN_RESOLUTIONS);
        self
    }
}

pub trait SplitTunnelStore: Send + Sync {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError>;
    fn save(&self, state: &StoredSplitTunnelState) -> Result<(), StorageError>;
    fn delete(&self) -> Result<(), StorageError>;
}

pub struct FileSplitTunnelStore {
    directory: PathBuf,
    path: PathBuf,
}

impl FileSplitTunnelStore {
    pub fn new(app_data_directory: impl AsRef<Path>) -> Self {
        let directory = app_data_directory.as_ref().join("split-tunnel");
        let path = directory.join("state.json");
        Self { directory, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SplitTunnelStore for FileSplitTunnelStore {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoredSplitTunnelState::default());
            }
            Err(error) => return Err(error.into()),
        };
        if file.metadata()?.len() > STATE_LIMIT_BYTES as u64 {
            return Err(StorageError::SplitTunnelStateTooLarge {
                limit_bytes: STATE_LIMIT_BYTES,
            });
        }

        let mut bytes = Vec::new();
        file.take((STATE_LIMIT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > STATE_LIMIT_BYTES {
            return Err(StorageError::SplitTunnelStateTooLarge {
                limit_bytes: STATE_LIMIT_BYTES,
            });
        }
        Ok(serde_json::from_slice::<StoredSplitTunnelState>(&bytes)?.normalized())
    }

    fn save(&self, state: &StoredSplitTunnelState) -> Result<(), StorageError> {
        let state = normalized_checked_state(state)?;
        let bytes = serde_json::to_vec(&state)?;
        create_protected_dir(&self.directory)?;

        let mut temporary = tempfile::Builder::new()
            .prefix(".state-")
            .suffix(".tmp")
            .tempfile_in(&self.directory)?;
        set_private_file_permissions(temporary.path())?;
        temporary.write_all(&bytes)?;
        temporary.as_file_mut().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| StorageError::Io(error.error))?;
        sync_directory(&self.directory)
    }

    fn delete(&self) -> Result<(), StorageError> {
        match fs::remove_file(&self.path) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Clone, Default)]
pub struct MemorySplitTunnelStore {
    state: Arc<Mutex<StoredSplitTunnelState>>,
}

impl SplitTunnelStore for MemorySplitTunnelStore {
    fn load(&self) -> Result<StoredSplitTunnelState, StorageError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| StorageError::SplitTunnelStateLock)
    }

    fn save(&self, state: &StoredSplitTunnelState) -> Result<(), StorageError> {
        *self
            .state
            .lock()
            .map_err(|_| StorageError::SplitTunnelStateLock)? = normalized_checked_state(state)?;
        Ok(())
    }

    fn delete(&self) -> Result<(), StorageError> {
        *self
            .state
            .lock()
            .map_err(|_| StorageError::SplitTunnelStateLock)? = StoredSplitTunnelState::default();
        Ok(())
    }
}

fn normalized_checked_state(
    state: &StoredSplitTunnelState,
) -> Result<StoredSplitTunnelState, StorageError> {
    let state = state.clone().normalized();
    if serde_json::to_vec(&state)?.len() > STATE_LIMIT_BYTES {
        return Err(StorageError::SplitTunnelStateTooLarge {
            limit_bytes: STATE_LIMIT_BYTES,
        });
    }
    Ok(state)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}
