//! Internal package identity and verified bytes. Neither type is a runtime IPC
//! payload; a UI can name an offer, never a path, URL or signing authority.
use crate::UpdateBackendError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod resume;
use resume::{file_identity, open_partial, open_partial_metadata, FileIdentity};
pub use resume::{DownloadValidator, PartialDownload, ResumedDownload};

const MAX_CACHE_METADATA_BYTES: u64 = 32 * 1024;
const STAGING_OWNER_SUFFIX: &str = ".owner";

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
    staging: Option<StagedFile>,
}

/// A download's pinned handle and its staging name. Cleanup must claim that
/// handle before removing anything at the name.
#[derive(Debug)]
pub struct StagedFile {
    file: Option<File>,
    path: PathBuf,
}

enum StagePublication {
    Published(File),
    Occupied(StagedFile),
}

impl StagedFile {
    fn from_parts(file: File, path: PathBuf) -> Self {
        Self {
            file: Some(file),
            path,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn as_file(&self) -> &File {
        self.file.as_ref().expect("staging handle already consumed")
    }

    /// Leave the staged bytes and their ownership record for startup recovery.
    pub fn keep(mut self) -> Result<(File, PathBuf), UpdateBackendError> {
        open_partial_metadata(self.as_file(), &self.path)?;
        Ok((
            self.file.take().expect("staging handle already consumed"),
            self.path.clone(),
        ))
    }

    fn publish(
        mut self,
        cache: &PreparedCache,
        destination: &Path,
    ) -> Result<StagePublication, UpdateBackendError> {
        if self.path.parent() != Some(cache.root.as_path())
            || destination.parent() != Some(cache.root.as_path())
            || !cache.can_resume_in_place()?
        {
            return Err(cache_error());
        }
        open_partial_metadata(self.as_file(), &self.path)?;
        let claimed = cache.claim_cache_entry(&self.path, self.as_file(), false)?;
        match claimed.promote(destination) {
            Ok(()) => Ok(StagePublication::Published(
                self.file.take().expect("staging handle already consumed"),
            )),
            Err(error) => {
                let occupied = error.kind() == io::ErrorKind::AlreadyExists
                    || fs::symlink_metadata(destination).is_ok();
                if claimed.restore()
                    && occupied
                    && open_partial_metadata(self.as_file(), &self.path).is_ok()
                {
                    Ok(StagePublication::Occupied(self))
                } else {
                    Err(cache_error())
                }
            }
        }
    }
}

impl Write for StagedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.as_file().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.as_file().flush()
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            release_staging(file, &self.path);
        }
    }
}

impl PreparedUpdate {
    /// Called by the platform backend ONLY after its native signature/package
    /// verification. Pins these exact bytes for later revalidation and install.
    pub fn from_verified_file(
        resolved: ResolvedUpdate,
        path: PathBuf,
    ) -> Result<Self, UpdateBackendError> {
        let digest = file_digest(&path)?;
        Self::from_verified_digest(resolved, path, digest)
    }

    fn from_verified_digest(
        resolved: ResolvedUpdate,
        path: PathBuf,
        (sha256, size_bytes): (String, u64),
    ) -> Result<Self, UpdateBackendError> {
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
                staging: None,
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
    let file = File::open(path).map_err(|_| error())?;
    digest_file(&file, meta.len())
}

fn digest_file(mut file: &File, expected_size: u64) -> Result<(String, u64), UpdateBackendError> {
    let error = || UpdateBackendError::new("update_cache_invalid");
    if expected_size == 0 {
        return Err(error());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| error())?;
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
    if size != expected_size {
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
    #[serde(default)]
    ownership: Option<CacheOwnership>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheOwnership {
    package: FileIdentity,
    sidecar: FileIdentity,
}

impl PreparedCache {
    pub fn open(root: PathBuf) -> Result<Self, UpdateBackendError> {
        if !root.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&root).map_err(|_| cache_error())?;
        }
        let cache = Self {
            root,
            live: std::sync::Mutex::new(Vec::new()),
        };
        cache.check_root()?;
        Ok(cache)
    }
    fn check_root(&self) -> Result<(), UpdateBackendError> {
        Self::check_root_at(&self.root)
    }

    fn check_root_at(root: &Path) -> Result<(), UpdateBackendError> {
        #[cfg(windows)]
        let trusted = resume::private_directory(root)?;
        #[cfg(not(windows))]
        let trusted = {
            let meta = fs::symlink_metadata(root).map_err(|_| cache_error())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // Temporary installers also require a directory with no other writer.
                if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
                    return Err(cache_error());
                }
            }
            meta.is_dir() && !meta.file_type().is_symlink()
        };
        trusted.then_some(()).ok_or_else(cache_error)
    }
    /// Called once at common-owner startup, before any consumer can be active.
    /// A downloaded package at/below the running version has already served its
    /// purpose. Foreign files and symlinks never belong to this cleanup.
    pub fn recover(&self, current_version: &str) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        let current = semver::Version::parse(current_version).map_err(|_| cache_error())?;
        self.recover_partial(&current)?;
        self.recover_staging(true)?;
        for key in self.cached_keys()? {
            if self.cache_metadata(&key).is_some_and(|(_, metadata)| {
                semver::Version::parse(&metadata.resolved.version)
                    .is_ok_and(|version| version <= current)
                    || path_absent(&self.package_path(&key))
            }) {
                let _ = self.remove_key(&key, false);
            }
        }
        Ok(())
    }

    fn cached_keys(&self) -> Result<Vec<String>, UpdateBackendError> {
        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|_| cache_error())? {
            let entry = entry.map_err(|_| cache_error())?;
            if let Some(key) = entry.file_name().to_str().and_then(package_sidecar_key) {
                keys.push(key.to_owned());
            }
        }
        Ok(keys)
    }

    fn package_path(&self, key: &str) -> PathBuf {
        self.root.join(format!("package-{key}.bin"))
    }

    fn metadata_path(&self, key: &str) -> PathBuf {
        self.root.join(format!("package-{key}.json"))
    }

    fn cache_metadata(&self, key: &str) -> Option<(File, CacheMetadata)> {
        let (file, metadata): (File, CacheMetadata) = read_cache_record(&self.metadata_path(key))?;
        if metadata.resolved.cache_key().ok().as_deref() != Some(key)
            || metadata
                .ownership
                .as_ref()
                .is_some_and(|ownership| !ownership.sidecar.matches(&file))
        {
            return None;
        }
        Some((file, metadata))
    }

    fn remove_key(&self, key: &str, consumer_finished: bool) -> Result<(), UpdateBackendError> {
        if !self.can_resume_in_place()? {
            return Ok(());
        }
        let package = self.package_path(key);
        if !consumer_finished
            && self
                .live
                .lock()
                .map_err(|_| cache_error())?
                .iter()
                .filter_map(|entry| entry.upgrade())
                .any(|entry| entry.path == package)
        {
            return Ok(());
        }
        let Some((sidecar, metadata)) = self.cache_metadata(key) else {
            return Ok(());
        };
        let Some(ownership) = metadata.ownership else {
            return Ok(());
        };
        let sidecar_path = self.metadata_path(key);
        let data = match open_partial(&package, false) {
            Ok(file) if ownership.package.matches(&file) => Some(file),
            Err(_) if path_absent(&package) => None,
            _ => return Ok(()),
        };
        self.remove_owned_pair(&sidecar_path, sidecar, &package, data)
    }

    fn remove_owned_pair(
        &self,
        record_path: &Path,
        record: File,
        data_path: &Path,
        data: Option<File>,
    ) -> Result<(), UpdateBackendError> {
        let record_claim = self.claim_cache_entry(record_path, &record, data.is_none())?;
        let data_claim = match data.as_ref() {
            Some(file) => match self.claim_cache_entry(data_path, file, true) {
                Ok(claim) => Some(claim),
                Err(error) => {
                    record_claim.restore();
                    return Err(error);
                }
            },
            None => None,
        };
        drop((record, data));
        let record_result = record_claim.remove();
        let data_result = data_claim.map_or(Ok(()), |claim| claim.remove());
        record_result.and(data_result)
    }

    /// Only the serialized platform consumer may call this after native return.
    pub fn consumed(&self, prepared: &PreparedUpdate) -> Result<(), UpdateBackendError> {
        if let Some(staging) = &prepared.file.staging {
            return if staging.path() == prepared.path()
                && prepared.path().parent() == Some(self.root.as_path())
            {
                Ok(())
            } else {
                Err(cache_error())
            };
        }
        let key = prepared.resolved().cache_key()?;
        if prepared.path() != self.package_path(&key) {
            return Err(cache_error());
        }
        self.remove_key(&key, true)
    }

    pub fn begin(&self) -> Result<StagedFile, UpdateBackendError> {
        self.begin_staging(".package-")
    }

    fn begin_staging(&self, prefix: &str) -> Result<StagedFile, UpdateBackendError> {
        self.begin_staging_for(prefix, None)
    }

    fn begin_staging_for(
        &self,
        prefix: &str,
        incoming: Option<&File>,
    ) -> Result<StagedFile, UpdateBackendError> {
        self.check_root()?;
        self.recover_staging(false)?;
        let temporary = tempfile::Builder::new()
            .prefix(prefix)
            .suffix(".part")
            .disable_cleanup(true)
            .make_in(&self.root, |path| {
                // Use a normal file handle so the Windows temporary attribute
                // does not follow the bytes into durable storage on rename.
                let mut options = fs::OpenOptions::new();
                options.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(path)
            })
            .map_err(|_| cache_error())?;
        let (handle, path) = temporary.into_parts();
        let file = StagedFile::from_parts(handle, path.to_path_buf());
        if let Ok(package) = file_identity(incoming.unwrap_or(file.as_file())) {
            let record_path = staging_record_path(file.path()).ok_or_else(cache_error)?;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(windows)]
            options.read(true); // Query the ownership record's extended attribute.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut record = options.open(record_path).map_err(|_| cache_error())?;
            let ownership = CacheOwnership {
                package,
                sidecar: file_identity(&record)?,
            };
            serde_json::to_writer(&mut record, &ownership).map_err(|_| cache_error())?;
            record.sync_all().map_err(|_| cache_error())?;
        }
        Ok(file)
    }

    fn recover_staging(&self, startup: bool) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        for entry in fs::read_dir(&self.root).map_err(|_| cache_error())? {
            let entry = entry.map_err(|_| cache_error())?;
            let name = entry.file_name();
            let Some(temporary) = name.to_str().and_then(staging_record_target) else {
                continue;
            };
            let path = self.root.join(temporary);
            let record_path = entry.path();
            let Some((record, ownership)) = read_cache_record::<CacheOwnership>(&record_path)
            else {
                continue;
            };
            if !staging_file_has_no_other_writers(&record) || !ownership.sidecar.matches(&record) {
                continue;
            }
            let data = if path_absent(&path) {
                None
            } else if startup {
                let Ok(file) = open_partial(&path, false) else {
                    continue;
                };
                if !staging_file_has_no_other_writers(&file) || !ownership.package.matches(&file) {
                    continue;
                }
                Some(file)
            } else {
                continue;
            };
            let _ = self.remove_owned_pair(&record_path, record, &path, data);
        }
        Ok(())
    }

    pub fn cached_path(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<Option<PathBuf>, UpdateBackendError> {
        Ok(self.open_cached_package(resolved)?.map(|(path, _)| path))
    }

    pub fn open_cached_package(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<Option<(PathBuf, File)>, UpdateBackendError> {
        self.check_root()?;
        let key = resolved.cache_key()?;
        let package = self.package_path(&key);
        let Some((_, metadata)) = self.cache_metadata(&key) else {
            return Ok(None);
        };
        if &metadata.resolved != resolved {
            return Ok(None);
        }
        let Ok(file) = open_partial(&package, false) else {
            return Ok(None);
        };
        if metadata
            .ownership
            .as_ref()
            .is_some_and(|ownership| !ownership.package.matches(&file))
        {
            return Ok(None);
        }
        let Ok(stat) = open_partial_metadata(&file, &package) else {
            return Ok(None);
        };
        match digest_file(&file, stat.len()) {
            Ok((digest, size))
                if digest == metadata.sha256
                    && size == metadata.size_bytes
                    && resolved.sha256.as_ref().is_none_or(|hash| hash == &digest)
                    && resolved.size_bytes.is_none_or(|expected| expected == size) =>
            {
                Ok(Some((package, file)))
            }
            _ => Ok(None),
        }
    }
    /// Re-admit the same cached file the platform checked, matching its verified
    /// digest and the current cache entries.
    pub fn admit_verified(
        &self,
        resolved: ResolvedUpdate,
        file: &File,
        verified_sha256: &str,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        self.check_root()?;
        let key = resolved.cache_key()?;
        let path = self.package_path(&key);
        let Some((sidecar, metadata)) = self.cache_metadata(&key) else {
            return Err(cache_error());
        };
        if metadata
            .ownership
            .as_ref()
            .is_some_and(|ownership| !ownership.package.matches(file))
        {
            return Err(cache_error());
        }
        let stat = open_partial_metadata(file, &path)?;
        let digest = digest_file(file, stat.len())?;
        let prepared = PreparedUpdate::from_verified_digest(resolved, path, digest)?;
        if &metadata.resolved != prepared.resolved()
            || metadata.sha256 != prepared.sha256()
            || verified_sha256 != prepared.sha256()
            || metadata.size_bytes != prepared.size_bytes()
        {
            return Err(UpdateBackendError::new("update_hash_mismatch"));
        }
        open_partial_metadata(file, prepared.path())?;
        open_partial_metadata(&sidecar, &self.metadata_path(&key))?;
        self.pin(&prepared)?;
        if metadata.ownership.is_some() {
            self.discard_verified_partials(prepared.resolved());
        }
        Ok(prepared)
    }

    fn pin(&self, prepared: &PreparedUpdate) -> Result<(), UpdateBackendError> {
        self.live
            .lock()
            .map_err(|_| cache_error())?
            .push(Arc::downgrade(&prepared.file));
        Ok(())
    }

    /// Commit the completed temporary file only if it still matches the digest
    /// obtained during platform signature verification.
    pub fn commit_verified(
        &self,
        temporary: StagedFile,
        resolved: ResolvedUpdate,
        verified_sha256: &str,
    ) -> Result<PreparedUpdate, UpdateBackendError> {
        self.check_root()?;
        if temporary.path().parent() != Some(self.root.as_path()) {
            return Err(cache_error());
        }
        temporary.as_file().sync_all().map_err(|_| cache_error())?;
        let handle = temporary.as_file();
        let metadata = open_partial_metadata(handle, temporary.path())?;
        let digest = digest_file(handle, metadata.len())?;
        if digest.0 != verified_sha256 {
            return Err(UpdateBackendError::new("update_hash_mismatch"));
        }
        let mut prepared = PreparedUpdate::from_verified_digest(
            resolved.clone(),
            temporary.path().to_owned(),
            digest,
        )?;
        let key = resolved.cache_key()?;
        let destination = self.package_path(&key);
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

        match self.publish_verified(temporary, &prepared, &key)? {
            Some(staging) => {
                open_partial_metadata(staging.as_file(), staging.path())?;
                Arc::get_mut(&mut prepared.file)
                    .ok_or_else(cache_error)?
                    .staging = Some(staging);
            }
            None => {
                Arc::get_mut(&mut prepared.file)
                    .ok_or_else(cache_error)?
                    .path = destination;
                self.pin(&prepared)?;
            }
        }
        self.prune_except(prepared.resolved())?;
        self.discard_verified_partials(prepared.resolved());
        Ok(prepared)
    }

    fn publish_verified(
        &self,
        temporary: StagedFile,
        prepared: &PreparedUpdate,
        key: &str,
    ) -> Result<Option<StagedFile>, UpdateBackendError> {
        let destination = self.package_path(key);
        let metadata_path = self.metadata_path(key);
        if !self.can_resume_in_place()? {
            return Ok(Some(temporary));
        }
        let Ok(package) = file_identity(temporary.as_file()) else {
            return Ok(Some(temporary));
        };
        if !path_absent(&destination) || !path_absent(&metadata_path) {
            // A replacement has been verified. Retire only the old pair whose
            // persisted identities still match both files.
            let _ = self.remove_key(key, false);
            if !path_absent(&destination) || !path_absent(&metadata_path) {
                return Ok(Some(temporary));
            }
        }
        let mut meta = self.begin_staging(".metadata-")?;
        let metadata = CacheMetadata {
            resolved: prepared.resolved().clone(),
            sha256: prepared.sha256().into(),
            size_bytes: prepared.size_bytes(),
            ownership: Some(CacheOwnership {
                package,
                sidecar: file_identity(meta.as_file())?,
            }),
        };
        serde_json::to_writer(&mut meta, &metadata).map_err(|_| cache_error())?;
        meta.flush().map_err(|_| cache_error())?;
        meta.as_file().sync_all().map_err(|_| cache_error())?;
        let file = match meta.publish(self, &metadata_path)? {
            StagePublication::Published(file) => file,
            StagePublication::Occupied(_) => return Ok(Some(temporary)),
        };
        let publication = temporary.publish(self, &destination);
        if !matches!(&publication, Ok(StagePublication::Published(_))) {
            if let Ok(claim) = self.claim_cache_entry(&metadata_path, &file, true) {
                drop(file);
                let _ = claim.remove();
            }
        }
        match publication? {
            StagePublication::Published(_) => Ok(None),
            StagePublication::Occupied(staging) => Ok(Some(staging)),
        }
    }

    pub fn prune_except(&self, keep: &ResolvedUpdate) -> Result<(), UpdateBackendError> {
        self.check_root()?;
        let keep = keep.cache_key()?;
        self.live
            .lock()
            .map_err(|_| cache_error())?
            .retain(|entry| entry.strong_count() > 0);
        for key in self.cached_keys()? {
            if key != keep {
                let _ = self.remove_key(&key, false);
            }
        }
        self.recover_staging(false)
    }
}

fn release_staging(file: File, path: &Path) {
    if open_partial_metadata(&file, path).is_err() {
        return;
    }
    let Some(root) = path.parent() else {
        return;
    };
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_staging_file)
    {
        return;
    }
    let record = staging_record_path(path).and_then(|record_path| {
        let (record, ownership) = read_cache_record::<CacheOwnership>(&record_path)?;
        (staging_file_has_no_other_writers(&record)
            && ownership.package.matches(&file)
            && ownership.sidecar.matches(&record))
        .then_some((record_path, record))
    });
    let claimed = PreparedCache::claim_cache_entry_in(root, path, &file, true);
    drop(file);
    let Ok(claimed) = claimed else {
        return;
    };
    if claimed.remove().is_err() {
        return;
    }
    if let Some((record_path, record)) = record {
        if let Ok(claimed) = PreparedCache::claim_cache_entry_in(root, &record_path, &record, true)
        {
            drop(record);
            let _ = claimed.remove();
        }
    }
}

fn staging_file_has_no_other_writers(file: &File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        file.metadata()
            .is_ok_and(|metadata| metadata.mode() & 0o022 == 0)
    }
    // Windows file_identity verifies the handle's owner and DACL.
    #[cfg(not(unix))]
    {
        let _ = file;
        true
    }
}

fn read_cache_record<T: serde::de::DeserializeOwned>(path: &Path) -> Option<(File, T)> {
    let file = open_partial(path, false).ok()?;
    if open_partial_metadata(&file, path).ok()?.len() > MAX_CACHE_METADATA_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_CACHE_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_CACHE_METADATA_BYTES {
        return None;
    }
    let record = serde_json::from_slice(&bytes).ok()?;
    Some((file, record))
}

fn path_absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn package_sidecar_key(name: &str) -> Option<&str> {
    let key = name.strip_prefix("package-")?.strip_suffix(".json")?;
    (key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(key)
}

fn is_staging_file(name: &str) -> bool {
    name.strip_prefix(".package-")
        .or_else(|| name.strip_prefix(".metadata-"))
        .and_then(|name| name.strip_suffix(".part"))
        .is_some_and(|name| {
            name.len() == 6 && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn staging_record_target(name: &str) -> Option<&str> {
    let name = name.strip_suffix(STAGING_OWNER_SUFFIX)?;
    is_staging_file(name).then_some(name)
}

fn staging_record_path(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!("{name}{STAGING_OWNER_SUFFIX}")))
}

fn is_staging_entry(name: &str) -> bool {
    is_staging_file(name) || staging_record_target(name).is_some()
}

fn is_prepared_entry(name: &str) -> bool {
    package_sidecar_key(name).is_some()
        || name
            .strip_prefix("package-")
            .and_then(|name| name.strip_suffix(".bin"))
            .is_some_and(|key| key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || is_staging_entry(name)
}

fn cache_error() -> UpdateBackendError {
    UpdateBackendError::new("update_cache_unavailable")
}
