//! Internal package identity and verified bytes. Neither type is a runtime IPC
//! payload; a UI can name an offer, never a path, URL or signing authority.
use crate::UpdateBackendError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedUpdate {
    pub version: String,
    pub target: String,
    pub artifact_url: String,
    pub signature: String,
    pub key_identity: String,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
}
impl ResolvedUpdate {
    pub fn cache_key(&self) -> Result<String, UpdateBackendError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|_| UpdateBackendError::new("update_identity_invalid"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone)]
pub struct PreparedUpdate {
    resolved: ResolvedUpdate,
    file: Arc<VerifiedFile>,
}
#[derive(Debug)]
struct VerifiedFile {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}
impl PreparedUpdate {
    /// Called by the platform backend ONLY after its native signature/package
    /// verification. Pins these exact bytes for later revalidation and install.
    pub fn from_verified_file(
        resolved: ResolvedUpdate,
        path: PathBuf,
    ) -> Result<Self, UpdateBackendError> {
        let (sha256, size_bytes) = file_digest(&path)?;
        if resolved
            .sha256
            .as_ref()
            .is_some_and(|expected| expected != &sha256)
            || resolved
                .size_bytes
                .is_some_and(|expected| expected != size_bytes)
        {
            return Err(UpdateBackendError::new("update_hash_mismatch"));
        }
        Ok(Self {
            resolved,
            file: Arc::new(VerifiedFile {
                path,
                sha256,
                size_bytes,
            }),
        })
    }
    pub fn resolved(&self) -> &ResolvedUpdate {
        &self.resolved
    }
    pub fn path(&self) -> &Path {
        &self.file.path
    }
    pub fn sha256(&self) -> &str {
        &self.file.sha256
    }
    pub fn size_bytes(&self) -> u64 {
        self.file.size_bytes
    }
    pub async fn revalidate_async(&self) -> Result<(), UpdateBackendError> {
        let prepared = self.clone();
        tokio::task::spawn_blocking(move || prepared.revalidate())
            .await
            .map_err(|_| UpdateBackendError::new("update_cache_invalid"))?
    }
    pub fn revalidate(&self) -> Result<(), UpdateBackendError> {
        let (digest, size) = file_digest(self.path())?;
        if digest != self.sha256() || size != self.size_bytes() {
            return Err(UpdateBackendError::new("update_hash_mismatch"));
        }
        Ok(())
    }
}
fn file_digest(path: &Path) -> Result<(String, u64), UpdateBackendError> {
    let error = || UpdateBackendError::new("update_cache_invalid");
    let meta = std::fs::symlink_metadata(path).map_err(|_| error())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() == 0 {
        return Err(error());
    }
    let mut file = std::fs::File::open(path).map_err(|_| error())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut size = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|_| error())?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hasher.update(&buffer[..count]);
    }
    if size != meta.len() {
        return Err(error());
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

/// One instance per common owner (which already holds the application owner
/// lock). Only exact files in this private directory belong to this cache.
pub struct PreparedCache {
    root: PathBuf,
    live: std::sync::Mutex<Vec<std::sync::Weak<VerifiedFile>>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    resolved: ResolvedUpdate,
    sha256: String,
    size_bytes: u64,
}
impl PreparedCache {
    pub fn open(root: PathBuf) -> Result<Self, UpdateBackendError> {
        if !root.exists() {
            std::fs::create_dir_all(&root).map_err(|_| cache_error())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| cache_error())?;
            }
        }
        let cache = Self {
            root,
            live: std::sync::Mutex::new(Vec::new()),
        };
        cache.check_root()?;
        Ok(cache)
    }
    fn check_root(&self) -> Result<(), UpdateBackendError> {
        let meta = std::fs::symlink_metadata(&self.root).map_err(|_| cache_error())?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(cache_error());
        }
        Ok(())
    }
    /// Called once at common-owner startup, before any consumer can be active.
    /// A downloaded package at/below the running version has already served its
    /// purpose. Foreign files and symlinks never belong to this cleanup.
    pub fn recover(&self, current_version: &str) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        let current = semver::Version::parse(current_version).map_err(|_| cache_error())?;
        for entry in std::fs::read_dir(&self.root).map_err(|_| cache_error())? {
            let entry = entry.map_err(|_| cache_error())?;
            let kind = entry.file_type().map_err(|_| cache_error())?;
            if !kind.is_file() || kind.is_symlink() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let temporary = name
                .strip_prefix(".package-")
                .or_else(|| name.strip_prefix(".metadata-"))
                .and_then(|n| n.strip_suffix(".part"))
                .is_some_and(|n| n.len() == 6 && n.bytes().all(|b| b.is_ascii_alphanumeric()));
            if temporary {
                std::fs::remove_file(entry.path()).map_err(|_| cache_error())?;
                continue;
            }
            let Some(key) = name
                .strip_prefix("package-")
                .and_then(|n| n.strip_suffix(".json"))
            else {
                continue;
            };
            if key.len() != 64
                || !key.bytes().all(|b| b.is_ascii_hexdigit())
                || entry.metadata().map_err(|_| cache_error())?.len() > 32 * 1024
            {
                continue;
            }
            let metadata: CacheMetadata = match std::fs::read(entry.path())
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(m) => m,
                None => continue,
            };
            if metadata.resolved.cache_key()? != key {
                continue;
            }
            if semver::Version::parse(&metadata.resolved.version)
                .is_ok_and(|version| version <= current)
            {
                self.remove_key(key, false)?;
            }
        }
        Ok(())
    }
    fn remove_key(&self, key: &str, consumer_finished: bool) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        let package = self.root.join(format!("package-{key}.bin"));
        if !consumer_finished
            && self
                .live
                .lock()
                .map_err(|_| cache_error())?
                .iter()
                .filter_map(|w| w.upgrade())
                .any(|f| f.path == package)
        {
            return Ok(());
        }
        for path in [self.root.join(format!("package-{key}.json")), package] {
            match std::fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
                    std::fs::remove_file(path).map_err(|_| cache_error())?
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(cache_error()),
            }
        }
        Ok(())
    }
    /// Only the serialized platform consumer may call this after native return.
    pub fn consumed(&self, prepared: &PreparedUpdate) -> Result<(), UpdateBackendError> {
        let key = prepared.resolved().cache_key()?;
        if prepared.path() != self.root.join(format!("package-{key}.bin")) {
            return Err(cache_error());
        }
        self.remove_key(&key, true)
    }
    pub fn begin(&self) -> Result<tempfile::NamedTempFile, UpdateBackendError> {
        self.check_root()?;
        tempfile::Builder::new()
            .prefix(".package-")
            .suffix(".part")
            .tempfile_in(&self.root)
            .map_err(|_| cache_error())
    }
    pub fn cached_path(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<Option<PathBuf>, UpdateBackendError> {
        self.check_root()?;
        let key = resolved.cache_key()?;
        let metadata_path = self.root.join(format!("package-{key}.json"));
        let package = self.root.join(format!("package-{key}.bin"));
        let meta = match std::fs::symlink_metadata(&metadata_path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(cache_error()),
        };
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 32 * 1024 {
            return Ok(None);
        }
        let metadata: CacheMetadata = match std::fs::read(&metadata_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(metadata) => metadata,
            None => return Ok(None),
        };
        if &metadata.resolved != resolved {
            return Ok(None);
        }
        match file_digest(&package) {
            Ok((digest, size))
                if digest == metadata.sha256
                    && size == metadata.size_bytes
                    && resolved.sha256.as_ref().is_none_or(|hash| hash == &digest)
                    && resolved.size_bytes.is_none_or(|expected| expected == size) =>
            {
                Ok(Some(package))
            }
            _ => Ok(None),
        }
    }
    /// Re-admit cached bytes only AFTER the platform rechecks the signature and
    /// native package identity. The metadata/hash alone do not grant authority.
    pub fn admit_verified(
        &self,
        resolved: ResolvedUpdate,
        path: PathBuf,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        self.check_root()?;
        if path
            != self
                .root
                .join(format!("package-{}.bin", resolved.cache_key()?))
        {
            return Err(cache_error());
        }
        let prepared = PreparedUpdate::from_verified_file(resolved, path)?;
        self.live
            .lock()
            .map_err(|_| cache_error())?
            .push(Arc::downgrade(&prepared.file));
        Ok(prepared)
    }
    /// The caller has verified the completed temporary file's signature. Flush
    /// and publish bytes before metadata; an interrupted commit is never ready.
    pub fn commit_verified(
        &self,
        temporary: tempfile::NamedTempFile,
        resolved: ResolvedUpdate,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        use std::io::Write;
        self.check_root()?;
        if temporary.path().parent() != Some(self.root.as_path()) {
            return Err(cache_error());
        }
        temporary.as_file().sync_all().map_err(|_| cache_error())?;
        let checked =
            PreparedUpdate::from_verified_file(resolved.clone(), temporary.path().to_owned())?;
        let key = resolved.cache_key()?;
        let destination = self.root.join(format!("package-{key}.bin"));
        let metadata_path = self.root.join(format!("package-{key}.json"));
        for path in [&destination, &metadata_path] {
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(cache_error());
                }
            }
        }
        if self
            .live
            .lock()
            .map_err(|_| cache_error())?
            .iter()
            .filter_map(|entry| entry.upgrade())
            .any(|entry| entry.path == destination)
        {
            return Err(UpdateBackendError::new("update_package_in_use"));
        }
        let metadata = CacheMetadata {
            resolved: resolved.clone(),
            sha256: checked.sha256().into(),
            size_bytes: checked.size_bytes(),
        };
        let mut meta = tempfile::Builder::new()
            .prefix(".metadata-")
            .suffix(".part")
            .tempfile_in(&self.root)
            .map_err(|_| cache_error())?;
        serde_json::to_writer(&mut meta, &metadata).map_err(|_| cache_error())?;
        meta.flush().map_err(|_| cache_error())?;
        meta.as_file().sync_all().map_err(|_| cache_error())?;
        temporary.persist(&destination).map_err(|_| cache_error())?;
        meta.persist(&metadata_path).map_err(|_| cache_error())?;
        let prepared = self.admit_verified(resolved, destination)?;
        self.prune_except(prepared.resolved())?;
        Ok(prepared)
    }
    pub fn prune_except(&self, keep: &ResolvedUpdate) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        let keep = keep.cache_key()?;
        let mut live = self.live.lock().map_err(|_| cache_error())?;
        live.retain(|entry| entry.strong_count() > 0);
        let live_paths: Vec<_> = live
            .iter()
            .filter_map(|entry| entry.upgrade())
            .map(|entry| entry.path.clone())
            .collect();
        for entry in std::fs::read_dir(&self.root).map_err(|_| cache_error())? {
            let entry = entry.map_err(|_| cache_error())?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(key) = name
                .strip_prefix("package-")
                .and_then(|s| s.strip_suffix(".bin").or_else(|| s.strip_suffix(".json")))
            else {
                continue;
            };
            if key.len() != 64 || !key.bytes().all(|c| c.is_ascii_hexdigit()) || key == keep {
                continue;
            }
            let package = self.root.join(format!("package-{key}.bin"));
            if live_paths.contains(&package) {
                continue;
            }
            let kind = entry.file_type().map_err(|_| cache_error())?;
            if kind.is_file() && !kind.is_symlink() {
                std::fs::remove_file(entry.path()).map_err(|_| cache_error())?;
            }
        }
        Ok(())
    }
}
fn cache_error() -> UpdateBackendError {
    UpdateBackendError::new("update_cache_unavailable")
}
