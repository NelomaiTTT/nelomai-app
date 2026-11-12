use super::{
    cache_error, PreparedCache, ResolvedUpdate, StagePublication, StagedFile, UpdateBackendError,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(windows)]
mod windows_identity;
#[cfg(any(windows, test))]
mod windows_security;

const MAX_PACKAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PARTIAL_METADATA_BYTES: u64 = 32 * 1024;
const PARTIAL_DATA: &str = "resume-download.bin";
const PARTIAL_METADATA: &str = "resume-download.json";
const ALTERNATE_DATA: &str = "resume-download-alternate.bin";
const ALTERNATE_METADATA: &str = "resume-download-alternate.json";
const CLAIM_PREFIX: &str = ".partial-move-";
const CLAIM_ENTRY: &str = "entry";
const CLAIM_IDENTITY: &str = "identity.json";

#[derive(Clone, Copy)]
struct CheckpointSlot {
    data: &'static str,
    metadata: &'static str,
}

const PRIMARY: CheckpointSlot = CheckpointSlot {
    data: PARTIAL_DATA,
    metadata: PARTIAL_METADATA,
};
const ALTERNATE: CheckpointSlot = CheckpointSlot {
    data: ALTERNATE_DATA,
    metadata: ALTERNATE_METADATA,
};
const CHECKPOINTS: [CheckpointSlot; 2] = [PRIMARY, ALTERNATE];

fn checkpoint_slot(is_alternate: bool) -> CheckpointSlot {
    if is_alternate {
        ALTERNATE
    } else {
        PRIMARY
    }
}

fn is_partial_entry(name: &str) -> bool {
    matches!(
        name,
        PARTIAL_DATA | PARTIAL_METADATA | ALTERNATE_DATA | ALTERNATE_METADATA
    )
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadValidator {
    url: String,
    etag: String,
    total: u64,
}

impl DownloadValidator {
    pub fn new(url: &str, etag: &str, total: u64) -> Option<Self> {
        let opaque = etag.strip_prefix('"')?.strip_suffix('"')?;
        if etag.len() > 256
            || !opaque
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"')
            || !(1..=MAX_PACKAGE_BYTES).contains(&total)
        {
            return None;
        }
        Some(Self {
            url: url.into(),
            etag: etag.into(),
            total,
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PartialMetadata {
    data_identity: FileIdentity,
    sidecar_identity: Option<FileIdentity>,
    artifact: String,
    version: String,
    validator: DownloadValidator,
    received: u64,
}

impl PartialMetadata {
    fn has_valid_artifact(&self) -> bool {
        self.artifact.len() == 64
            && self.artifact.bytes().all(|byte| byte.is_ascii_hexdigit())
            && semver::Version::parse(&self.version).is_ok()
    }

    fn accepts_file_size(&self, size: u64) -> bool {
        (self.received..=self.validator.total()).contains(&size)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileIdentity {
    volume: u64,
    index: u64,
    created: Option<(u64, u32)>,
    #[cfg(windows)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    windows_token: Option<[u8; 16]>,
}

impl FileIdentity {
    pub(super) fn matches(&self, file: &File) -> bool {
        let Ok(Some(identity)) = file_stat_identity(file) else {
            return false;
        };
        if self.index != identity.index || (!cfg!(unix) && self.volume != identity.volume) {
            return false;
        }
        #[cfg(windows)]
        if let Some(token) = self.windows_token {
            return windows_identity::read(file).is_ok_and(|actual| actual == Some(token));
        }
        self.created == identity.created
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRecord {
    identity: FileIdentity,
    original: String,
    #[serde(default)]
    discard: bool,
}

pub struct PartialDownload {
    path: PathBuf,
    slot: CheckpointSlot,
    metadata: PartialMetadata,
    file: File,
    sidecar: File,
    resumable: bool,
}

impl PartialDownload {
    pub fn received(&self) -> u64 {
        self.metadata.received
    }

    pub fn validator(&self) -> &DownloadValidator {
        &self.metadata.validator
    }

    pub fn etag_for(&self, url: &str) -> Option<&str> {
        (self.resumable && self.metadata.validator.url == url)
            .then_some(self.metadata.validator.etag.as_str())
    }

    pub fn accepts_range(&self, url: &str, etag: &str, range: &str, length: Option<u64>) -> bool {
        let total = self.validator().total();
        self.etag_for(url) == Some(etag)
            && byte_range(range) == Some((self.received(), total - 1, total))
            && length.is_none_or(|length| length == total - self.received())
    }

    fn accepts_file_size(&self, size: u64) -> bool {
        self.metadata.accepts_file_size(size)
    }
}

fn byte_range(header: &str) -> Option<(u64, u64, u64)> {
    fn decimal(value: &str) -> Option<u64> {
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            value.parse().ok()
        } else {
            None
        }
    }

    let (unit, range) = header.split_once(' ')?;
    if !unit.eq_ignore_ascii_case("bytes") {
        return None;
    }
    let (positions, total) = range.split_once('/')?;
    let (first, last) = positions.split_once('-')?;
    Some((decimal(first)?, decimal(last)?, decimal(total)?))
}

/// The serialized downloader appends to the cache-owned partial. Until its
/// checkpoint is published, a later attempt resumes from the previous length.
pub struct ResumedDownload {
    saved: PartialDownload,
}

impl Write for ResumedDownload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.saved.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.saved.file.flush()
    }
}

impl PreparedCache {
    pub fn partial(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<Option<PartialDownload>, UpdateBackendError> {
        Ok(self
            .download_partial(resolved)?
            .filter(|saved| saved.resumable))
    }

    /// Pin an owned checkpoint before HTTP. A prior artifact may be reclaimed
    /// after a valid full response, but cannot authorize a range request.
    pub fn download_partial(
        &self,
        resolved: &ResolvedUpdate,
    ) -> Result<Option<PartialDownload>, UpdateBackendError> {
        self.download_partial_for(resolved, false)
    }

    /// Pin the checkpoint for the selected request origin.
    pub fn download_partial_for(
        &self,
        resolved: &ResolvedUpdate,
        is_alternate: bool,
    ) -> Result<Option<PartialDownload>, UpdateBackendError> {
        self.open_checkpoint(Some(resolved), checkpoint_slot(is_alternate))
    }

    fn open_checkpoint(
        &self,
        resolved: Option<&ResolvedUpdate>,
        slot: CheckpointSlot,
    ) -> Result<Option<PartialDownload>, UpdateBackendError> {
        if !self.can_resume_in_place()? {
            return Ok(None);
        }
        let Some((sidecar, metadata)) = self.open_owned_sidecar(slot)? else {
            return Ok(None);
        };
        if !metadata.has_valid_artifact() {
            return Ok(None);
        }
        let resumable = match resolved {
            Some(resolved) => {
                metadata.artifact == resolved.cache_key()?
                    && resolved
                        .size_bytes
                        .is_none_or(|size| size == metadata.validator.total)
            }
            None => false,
        };
        let path = self.root.join(slot.data);
        let Ok(file) = open_partial(&path, resumable) else {
            return Ok(None);
        };
        let saved = PartialDownload {
            path,
            slot,
            metadata,
            file,
            sidecar,
            resumable,
        };
        if !saved.metadata.data_identity.matches(&saved.file)
            || open_partial_metadata(&saved.file, &saved.path).map_or(true, |metadata| {
                resolved.is_some() && !saved.accepts_file_size(metadata.len())
            })
        {
            return Ok(None);
        }
        Ok(Some(saved))
    }

    fn open_owned_sidecar(
        &self,
        slot: CheckpointSlot,
    ) -> Result<Option<(File, PartialMetadata)>, UpdateBackendError> {
        let path = self.root.join(slot.metadata);
        let Ok(sidecar) = open_partial(&path, false) else {
            return Ok(None);
        };
        if !open_partial_metadata(&sidecar, &path)
            .is_ok_and(|metadata| metadata.len() <= MAX_PARTIAL_METADATA_BYTES)
        {
            return Ok(None);
        }
        let Some(metadata) = read_owned_partial_metadata(&sidecar)? else {
            return Ok(None);
        };
        Ok(Some((sidecar, metadata)))
    }

    fn checkpoint_supersedes(&self, slot: CheckpointSlot, previous: PartialMetadata) -> bool {
        let Ok(Some(saved)) = self.open_checkpoint(None, slot) else {
            return false;
        };
        saved.received() >= previous.received
            && saved.metadata.artifact == previous.artifact
            && saved.metadata.version == previous.version
            && saved.metadata.validator == previous.validator
            && previous.data_identity.matches(&saved.file)
            && self
                .check_partial_owner(&saved)
                .is_ok_and(|metadata| saved.accepts_file_size(metadata.len()))
    }

    pub fn begin_resume(
        &self,
        mut saved: PartialDownload,
    ) -> Result<ResumedDownload, UpdateBackendError> {
        let size = self.check_partial_owner(&saved)?.len();
        if !saved.resumable || !saved.accepts_file_size(size) {
            return Err(cache_error());
        }
        if size != saved.received() {
            // A cancelled request or crash may have written beyond the last
            // durable checkpoint. Only the checkpoint was admitted for Range.
            saved
                .file
                .set_len(saved.received())
                .map_err(|_| cache_error())?;
        }
        saved
            .file
            .seek(SeekFrom::Start(saved.received()))
            .map_err(|_| cache_error())?;
        Ok(ResumedDownload { saved })
    }

    fn check_partial_owner(&self, saved: &PartialDownload) -> Result<Metadata, UpdateBackendError> {
        if !self.can_resume_in_place()? || saved.path != self.root.join(saved.slot.data) {
            return Err(cache_error());
        }
        self.check_partial_sidecar(saved)?;
        if !saved.metadata.data_identity.matches(&saved.file) {
            return Err(cache_error());
        }
        open_partial_metadata(&saved.file, &saved.path)
    }

    fn check_partial_sidecar(&self, saved: &PartialDownload) -> Result<(), UpdateBackendError> {
        #[cfg(windows)]
        if !windows_security::private_file(&saved.sidecar) {
            return Err(cache_error());
        }
        let path = self.root.join(saved.slot.metadata);
        if open_partial_metadata(&saved.sidecar, &path)?.len() > MAX_PARTIAL_METADATA_BYTES
            || read_partial_metadata(&saved.sidecar)?.as_ref() != Some(&saved.metadata)
        {
            return Err(cache_error());
        }
        Ok(())
    }

    pub(super) fn can_resume_in_place(&self) -> Result<bool, UpdateBackendError> {
        self.check_root()?;
        #[cfg(windows)]
        return Ok(true);
        #[cfg(not(windows))]
        private_directory(&self.root)
    }

    pub fn checkpoint_resume(&self, resumed: ResumedDownload) -> Result<(), UpdateBackendError> {
        let ResumedDownload { saved } = resumed;
        let received = self.check_partial_owner(&saved)?.len();
        if (saved.received() + 1..saved.validator().total()).contains(&received) {
            saved.file.sync_all().map_err(|_| cache_error())?;
            let mut metadata = saved.metadata.clone();
            metadata.received = received;
            let sidecar = self.partial_sidecar(metadata)?;
            if self.check_partial_owner(&saved)?.len() != received {
                return Err(cache_error());
            }
            let path = self.root.join(saved.slot.metadata);
            let old_sidecar = self.claim_sidecar(&saved)?;
            drop(saved);
            match sidecar.publish(self, &path) {
                Ok(StagePublication::Published(_)) => old_sidecar.remove()?,
                Ok(StagePublication::Occupied(_)) | Err(_) => {
                    old_sidecar.restore();
                    return Err(cache_error());
                }
            }
        }
        Ok(())
    }

    pub fn finish_resume(
        &self,
        resumed: ResumedDownload,
    ) -> Result<StagedFile, UpdateBackendError> {
        let ResumedDownload { saved } = resumed;
        if self.check_partial_owner(&saved)?.len() != saved.validator().total() {
            return Err(cache_error());
        }
        let placeholder = self.begin_staging_for(".package-", Some(&saved.file))?;
        let path = placeholder.path().to_owned();
        drop(placeholder);
        let data = self.claim_entry(&saved.path, &saved.file)?;
        if data.promote(&path).is_err() {
            data.restore();
            return Err(cache_error());
        }
        // A replacement sidecar belongs to another operation even though the
        // completed data has been isolated and can proceed to verification.
        if let Ok(sidecar) = self.claim_sidecar(&saved) {
            drop(saved.sidecar);
            let _ = sidecar.remove();
        }
        Ok(StagedFile::from_parts(saved.file, path))
    }

    pub fn save_partial(
        &self,
        temporary: StagedFile,
        resolved: &ResolvedUpdate,
        validator: &DownloadValidator,
    ) -> Result<(), UpdateBackendError> {
        if temporary.path().parent() != Some(self.root.as_path()) {
            return Err(cache_error());
        }
        if !self.can_resume_in_place()? {
            return Ok(());
        }
        let received = temporary
            .as_file()
            .metadata()
            .map_err(|_| cache_error())?
            .len();
        if !(1..validator.total).contains(&received) {
            return Ok(());
        }
        let slot = checkpoint_slot(validator.url != resolved.artifact_url);
        let data = self.root.join(slot.data);
        let checkpoint = self.root.join(slot.metadata);
        if [&data, &checkpoint]
            .iter()
            .any(|path| fs::symlink_metadata(path).is_ok())
        {
            return Ok(());
        }
        temporary.as_file().sync_all().map_err(|_| cache_error())?;
        let metadata = PartialMetadata {
            data_identity: match file_identity(temporary.as_file()) {
                Ok(identity) => identity,
                Err(_) => return Ok(()),
            },
            sidecar_identity: None,
            artifact: resolved.cache_key()?,
            version: resolved.version.clone(),
            validator: validator.clone(),
            received,
        };
        let sidecar = self.partial_sidecar(metadata)?;
        // Publish the identity first. A crash before the data move leaves only
        // an identifiable, small orphan instead of an unbound package prefix.
        let file = match sidecar.publish(self, &checkpoint)? {
            StagePublication::Published(file) => file,
            StagePublication::Occupied(_) => return Ok(()),
        };
        let publication = temporary.publish(self, &data);
        if !matches!(&publication, Ok(StagePublication::Published(_))) {
            if let Ok(claimed) = self.claim_entry(&checkpoint, &file) {
                drop(file);
                let _ = claimed.remove();
            }
        }
        publication.map(|_| ())
    }

    fn partial_sidecar(
        &self,
        mut metadata: PartialMetadata,
    ) -> Result<StagedFile, UpdateBackendError> {
        let mut sidecar = self.begin_staging(".metadata-")?;
        metadata.sidecar_identity = Some(file_identity(sidecar.as_file())?);
        serde_json::to_writer(&mut sidecar, &metadata).map_err(|_| cache_error())?;
        sidecar.flush().map_err(|_| cache_error())?;
        sidecar.as_file().sync_all().map_err(|_| cache_error())?;
        Ok(sidecar)
    }

    pub fn discard_admitted_partial(
        &self,
        saved: PartialDownload,
    ) -> Result<(), UpdateBackendError> {
        if !self
            .check_partial_owner(&saved)
            .is_ok_and(|metadata| saved.accepts_file_size(metadata.len()))
        {
            return Ok(());
        }
        self.discard_checkpoint(saved)
    }

    fn discard_checkpoint(&self, saved: PartialDownload) -> Result<(), UpdateBackendError> {
        let sidecar = self.claim_sidecar(&saved)?;
        // Once the data is isolated, finish this discard on restart even
        // if the sidecar has already been removed.
        let data = match self.claim_cache_entry(&saved.path, &saved.file, true) {
            Ok(data) => data,
            Err(error) => {
                sidecar.restore();
                return Err(error);
            }
        };
        // Close the pinned handles before removing their isolated names, so
        // Windows can reclaim the storage before a fresh body starts.
        drop(saved);
        let metadata_result = sidecar.remove();
        let data_result = data.remove();
        metadata_result.and(data_result)
    }

    fn claim_sidecar(&self, saved: &PartialDownload) -> Result<ClaimedEntry, UpdateBackendError> {
        self.check_partial_sidecar(saved)?;
        let path = self.root.join(saved.slot.metadata);
        let sidecar = self.claim_entry(&path, &saved.sidecar)?;
        if read_partial_metadata(&saved.sidecar)
            .ok()
            .flatten()
            .as_ref()
            != Some(&saved.metadata)
        {
            sidecar.restore();
            return Err(cache_error());
        }
        Ok(sidecar)
    }

    /// Isolate the name before deciding whether its entry belongs to the
    /// download. A replacement must never be deleted or used as a package.
    fn claim_entry(&self, path: &Path, file: &File) -> Result<ClaimedEntry, UpdateBackendError> {
        self.claim_cache_entry(path, file, false)
    }

    pub(super) fn claim_cache_entry(
        &self,
        path: &Path,
        file: &File,
        discard: bool,
    ) -> Result<ClaimedEntry, UpdateBackendError> {
        Self::claim_cache_entry_in(&self.root, path, file, discard)
    }

    pub(super) fn claim_cache_entry_in(
        root: &Path,
        path: &Path,
        file: &File,
        discard: bool,
    ) -> Result<ClaimedEntry, UpdateBackendError> {
        if path.parent() != Some(root) {
            return Err(cache_error());
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(cache_error)?;
        let staging = super::is_staging_entry(name);
        if staging {
            Self::check_root_at(root)?;
            if !super::staging_file_has_no_other_writers(file) {
                return Err(cache_error());
            }
        } else if (!is_partial_entry(name) && !super::is_prepared_entry(name))
            || !private_directory(root)?
        {
            return Err(cache_error());
        }
        let identity = durable_file_identity(file)?;
        if identity.is_none() && !staging {
            return Err(cache_error());
        }
        let mut builder = tempfile::Builder::new();
        builder.prefix(CLAIM_PREFIX);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            builder.permissions(fs::Permissions::from_mode(0o700));
        }
        let directory = builder.tempdir_in(root).map_err(|_| cache_error())?;
        if let Some(identity) = identity {
            let record = ClaimRecord {
                identity,
                original: name.into(),
                discard,
            };
            let mut journal = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.path().join(CLAIM_IDENTITY))
                .map_err(|_| cache_error())?;
            serde_json::to_writer(&mut journal, &record).map_err(|_| cache_error())?;
            journal.sync_all().map_err(|_| cache_error())?;
        }
        // A staging claim without birth time has no journal. The live handle
        // can authorize this move, but restart cannot authorize its removal.
        // No recursive cleanup may run after the move until ownership is known.
        let claimed = ClaimedEntry {
            directory: directory.keep(),
            original: path.to_owned(),
        };
        #[cfg(test)]
        tests::before_move(path);
        if fs::rename(path, claimed.entry()).is_err() {
            claimed.clear();
            return Err(cache_error());
        }
        #[cfg(test)]
        tests::after_move(path);
        if open_partial_metadata(file, &claimed.entry()).is_err() {
            claimed.restore();
            return Err(cache_error());
        }
        Ok(claimed)
    }

    pub fn discard_partial(&self) -> Result<(), UpdateBackendError> {
        for slot in CHECKPOINTS {
            if let Some(saved) = self.open_checkpoint(None, slot)? {
                self.discard_checkpoint(saved)?;
            }
        }
        Ok(())
    }

    pub(super) fn discard_verified_partials(&self, resolved: &ResolvedUpdate) {
        for slot in CHECKPOINTS {
            if let Ok(Some(saved)) = self.open_checkpoint(Some(resolved), slot) {
                if saved.resumable {
                    let _ = self.discard_admitted_partial(saved);
                }
            }
        }
    }

    pub(super) fn recover_partial(
        &self,
        installed: &semver::Version,
    ) -> Result<(), UpdateBackendError> {
        let canonical = self.can_resume_in_place()?;
        // Restore crash-left owned entries to vacant names before evaluating
        // the checkpoint. A mismatched entry in a claim remains protected.
        let claim_directories = fs::read_dir(&self.root)
            .map_err(|_| cache_error())?
            .flatten()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(CLAIM_PREFIX))
            })
            .map(|entry| entry.path());
        let pending_data = self.recover_claims(claim_directories, canonical);
        if !canonical {
            return Ok(());
        }
        for (slot, data_pending) in CHECKPOINTS.into_iter().zip(pending_data) {
            #[cfg(test)]
            tests::after_claim_recovery(&self.root.join(slot.data));
            if let Ok(Some(saved)) = self.open_checkpoint(None, slot) {
                let obsolete = semver::Version::parse(&saved.metadata.version)
                    .is_ok_and(|version| version <= *installed);
                let incomplete = saved
                    .file
                    .metadata()
                    .is_ok_and(|metadata| !saved.accepts_file_size(metadata.len()));
                if obsolete || incomplete {
                    let _ = self.discard_checkpoint(saved);
                }
            } else if !data_pending
                && fs::symlink_metadata(self.root.join(slot.data))
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                if let Ok(Some((sidecar, _))) = self.open_owned_sidecar(slot) {
                    if let Ok(claimed) = self.claim_entry(&self.root.join(slot.metadata), &sidecar)
                    {
                        drop(sidecar);
                        let _ = claimed.remove();
                    }
                }
            }
        }
        Ok(())
    }

    fn recover_claims(
        &self,
        directories: impl IntoIterator<Item = PathBuf>,
        canonical: bool,
    ) -> [bool; CHECKPOINTS.len()] {
        let mut pending_data = [false; CHECKPOINTS.len()];
        let mut sidecars = Vec::new();
        for directory in directories {
            recover_claim(
                self,
                &directory,
                canonical,
                &mut pending_data,
                Some(&mut sidecars),
            );
        }
        // Resolve any data claims before deciding which sidecar can restore the
        // highest durable offset for that data.
        sidecars.sort_by_cached_key(|sidecar| {
            (
                Reverse(sidecar.recoverable_offset(&self.root)),
                sidecar.directory.clone(),
            )
        });
        for sidecar in sidecars {
            recover_claim(self, &sidecar.directory, canonical, &mut pending_data, None);
        }
        pending_data
    }
}

struct CheckpointSidecarClaim {
    directory: PathBuf,
    slot: CheckpointSlot,
    metadata: Option<PartialMetadata>,
}

impl CheckpointSidecarClaim {
    fn recoverable_offset(&self, root: &Path) -> u64 {
        let Some(metadata) = self
            .metadata
            .as_ref()
            .filter(|metadata| metadata.has_valid_artifact())
        else {
            return 0;
        };
        let path = root.join(self.slot.data);
        let Ok(file) = open_partial(&path, false) else {
            return 0;
        };
        if metadata.data_identity.matches(&file)
            && open_partial_metadata(&file, &path)
                .is_ok_and(|stat| metadata.accepts_file_size(stat.len()))
        {
            metadata.received
        } else {
            0
        }
    }
}

pub(super) struct ClaimedEntry {
    directory: PathBuf,
    original: PathBuf,
}

impl ClaimedEntry {
    fn entry(&self) -> PathBuf {
        self.directory.join(CLAIM_ENTRY)
    }

    fn clear(&self) {
        clear_claim(&self.directory);
    }

    pub(super) fn restore(self) -> bool {
        self.promote(&self.original).is_ok()
    }

    pub(super) fn promote(&self, path: &Path) -> io::Result<()> {
        move_without_clobber(&self.entry(), path)?;
        self.clear();
        Ok(())
    }

    pub(super) fn remove(self) -> Result<(), UpdateBackendError> {
        #[cfg(test)]
        if tests::remove_fails(&self.original) {
            return Err(cache_error());
        }
        fs::remove_file(self.entry()).map_err(|_| cache_error())?;
        self.clear();
        Ok(())
    }
}

fn clear_claim(directory: &Path) {
    let _ = fs::remove_file(directory.join(CLAIM_IDENTITY));
    let _ = fs::remove_dir(directory);
}

fn recover_claim(
    cache: &PreparedCache,
    directory: &Path,
    canonical: bool,
    pending_data: &mut [bool; CHECKPOINTS.len()],
    defer_sidecars: Option<&mut Vec<CheckpointSidecarClaim>>,
) {
    if !private_directory(directory).unwrap_or(false) {
        return;
    }
    let record_path = directory.join(CLAIM_IDENTITY);
    let Ok(record) = open_partial(&record_path, false) else {
        return;
    };
    if !open_partial_metadata(&record, &record_path).is_ok_and(|metadata| metadata.len() <= 1024) {
        return;
    }
    #[cfg(windows)]
    if !windows_security::private_file(&record) {
        return;
    }
    let Ok(record) = serde_json::from_reader::<_, ClaimRecord>(record.take(1024)) else {
        return;
    };
    if !super::is_staging_entry(&record.original)
        && (!canonical
            || (!is_partial_entry(&record.original) && !super::is_prepared_entry(&record.original)))
    {
        return;
    }
    let path = directory.join(CLAIM_ENTRY);
    if fs::symlink_metadata(&path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound) {
        clear_claim(directory);
        return;
    }
    let Ok(file) = open_partial(&path, false) else {
        return;
    };
    if !record.identity.matches(&file)
        || open_partial_metadata(&file, &path).is_err()
        || (super::is_staging_entry(&record.original)
            && !super::staging_file_has_no_other_writers(&file))
    {
        return;
    }
    let slot = CHECKPOINTS
        .into_iter()
        .find(|slot| slot.metadata == record.original);
    let previous = slot
        .filter(|_| !record.discard)
        .and_then(|_| read_owned_partial_metadata(&file).ok().flatten());
    drop(file);
    if let (Some(slot), Some(sidecars)) = (slot.filter(|_| !record.discard), defer_sidecars) {
        sidecars.push(CheckpointSidecarClaim {
            directory: directory.to_owned(),
            slot,
            metadata: previous,
        });
        return;
    }
    let claimed = ClaimedEntry {
        directory: directory.to_owned(),
        original: cache.root.join(&record.original),
    };
    if record.discard {
        let _ = claimed.remove();
    } else if move_without_clobber(&path, &claimed.original).is_ok() {
        claimed.clear();
    } else if let Some(index) = CHECKPOINTS
        .iter()
        .position(|slot| slot.data == record.original)
    {
        // A data claim awaiting restoration still needs its sidecar.
        pending_data[index] = true;
    } else {
        let superseded = match slot {
            Some(slot) => previous.is_some_and(|old| cache.checkpoint_supersedes(slot, old)),
            None => fs::symlink_metadata(&claimed.original).is_ok(),
        };
        if superseded {
            let _ = claimed.remove();
        }
    }
}

fn move_without_clobber(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        let mut path = tempfile::TempPath::try_from_path(source)?;
        path.disable_cleanup(true);
        path.persist_noclobber(destination)
            .map_err(|error| error.error)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

        let wide_path = |path: &Path| -> io::Result<Vec<u16>> {
            let parent = fs::canonicalize(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
            Ok(parent
                .join(path.file_name().ok_or(io::ErrorKind::InvalidInput)?)
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect())
        };
        let source = wide_path(source)?;
        let destination = wide_path(destination)?;
        if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn private_directory(path: &Path) -> Result<bool, UpdateBackendError> {
    Ok(windows_security::private_directory(path))
}

#[cfg(not(windows))]
fn private_directory(path: &Path) -> Result<bool, UpdateBackendError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| cache_error())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    Ok(false)
}

fn read_partial_metadata(mut file: &File) -> Result<Option<PartialMetadata>, UpdateBackendError> {
    file.seek(SeekFrom::Start(0)).map_err(|_| cache_error())?;
    let mut bytes = Vec::new();
    file.take(MAX_PARTIAL_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| cache_error())?;
    if bytes.len() as u64 > MAX_PARTIAL_METADATA_BYTES {
        return Ok(None);
    }
    let metadata: PartialMetadata = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let validator = &metadata.validator;
    Ok(
        (DownloadValidator::new(&validator.url, &validator.etag, validator.total).is_some()
            && (1..validator.total).contains(&metadata.received))
        .then_some(metadata),
    )
}

fn read_owned_partial_metadata(file: &File) -> Result<Option<PartialMetadata>, UpdateBackendError> {
    Ok(read_partial_metadata(file)?.filter(|metadata| {
        metadata
            .sidecar_identity
            .as_ref()
            .is_some_and(|identity| identity.matches(file))
    }))
}

pub(super) fn file_identity(file: &File) -> Result<FileIdentity, UpdateBackendError> {
    let identity = durable_file_identity(file)?.ok_or_else(cache_error)?;
    #[cfg(windows)]
    let identity = {
        let mut identity = identity;
        if identity.windows_token.is_none() {
            identity.windows_token = windows_identity::create(file).map_err(|_| cache_error())?;
            if identity.windows_token.is_some() {
                identity.created = None;
            }
        }
        identity
    };
    Ok(identity)
}

fn durable_file_identity(file: &File) -> Result<Option<FileIdentity>, UpdateBackendError> {
    let Some(identity) = file_stat_identity(file)? else {
        return Ok(None);
    };
    #[cfg(windows)]
    let identity = {
        let mut identity = identity;
        identity.windows_token = windows_identity::read(file).map_err(|_| cache_error())?;
        if identity.windows_token.is_some() {
            identity.created = None;
        }
        identity
    };
    Ok(Some(identity))
}

fn file_stat_identity(file: &File) -> Result<Option<FileIdentity>, UpdateBackendError> {
    let metadata = file.metadata().map_err(|_| cache_error())?;
    if !metadata.is_file() {
        return Err(cache_error());
    }
    let created = metadata.created().ok().and_then(|created| {
        created
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| (duration.as_secs(), duration.subsec_nanos()))
    });
    #[cfg(all(unix, test))]
    let created = if tests::omits_birth_time() {
        None
    } else {
        created
    };
    #[cfg(unix)]
    let (volume, index) = {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(cache_error());
        }
        // st_dev describes the current mount and can change on remount.
        // The live pathname comparison below still checks both dev and ino.
        if created.is_none() {
            return Ok(None);
        }
        (0, metadata.ino())
    };
    #[cfg(windows)]
    let (volume, index) = {
        if !windows_security::private_file(file) {
            return Err(cache_error());
        }
        let (volume, high, low) = windows_file_identity(file)?;
        (u64::from(volume), (u64::from(high) << 32) | u64::from(low))
    };
    #[cfg(not(any(unix, windows)))]
    return Err(cache_error());
    Ok(Some(FileIdentity {
        volume,
        index,
        created,
        #[cfg(windows)]
        windows_token: None,
    }))
}

pub(super) fn open_partial_metadata(
    file: &File,
    path: &Path,
) -> Result<Metadata, UpdateBackendError> {
    let metadata = file.metadata().map_err(|_| cache_error())?;
    if !metadata.is_file() {
        return Err(cache_error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = fs::symlink_metadata(path).map_err(|_| cache_error())?;
        if !current.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.dev() != current.dev()
            || metadata.ino() != current.ino()
            || metadata.nlink() != 1
        {
            return Err(cache_error());
        }
    }
    #[cfg(windows)]
    if windows_file_identity(file)? != windows_file_identity(&open_partial(path, false)?)? {
        return Err(cache_error());
    }
    Ok(metadata)
}

pub(super) fn open_partial(path: &Path, writable: bool) -> Result<File, UpdateBackendError> {
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|_| cache_error())
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<(u32, u32, u32), UpdateBackendError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.nNumberOfLinks != 1
        || info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(cache_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    type MoveHook = (String, Box<dyn FnOnce(&Path)>);
    thread_local! {
        static BEFORE_MOVE: RefCell<Option<MoveHook>> = RefCell::new(None);
        static AFTER_MOVE: RefCell<Option<MoveHook>> = RefCell::new(None);
        static AFTER_CLAIM_RECOVERY: RefCell<Option<MoveHook>> = RefCell::new(None);
        static FAIL_REMOVE: Cell<Option<&'static str>> = const { Cell::new(None) };
    }

    #[cfg(unix)]
    thread_local! {
        static OMIT_BIRTH_TIME: Cell<bool> = const { Cell::new(false) };
    }

    #[cfg(unix)]
    pub(super) fn omits_birth_time() -> bool {
        OMIT_BIRTH_TIME.get()
    }

    pub(super) fn before_move(path: &Path) {
        BEFORE_MOVE.with(|hook| run_hook(hook, path));
    }

    pub(super) fn after_move(path: &Path) {
        AFTER_MOVE.with(|hook| run_hook(hook, path));
    }

    pub(super) fn after_claim_recovery(path: &Path) {
        AFTER_CLAIM_RECOVERY.with(|hook| run_hook(hook, path));
    }

    pub(super) fn remove_fails(path: &Path) -> bool {
        FAIL_REMOVE.with(|name| {
            if name
                .get()
                .is_some_and(|name| path.file_name() == Some(name.as_ref()))
            {
                name.take();
                true
            } else {
                false
            }
        })
    }

    fn run_hook(hook: &RefCell<Option<MoveHook>>, path: &Path) {
        if hook
            .borrow()
            .as_ref()
            .is_some_and(|(name, _)| path.file_name().unwrap() == name.as_str())
        {
            if let Some((_, hook)) = hook.take() {
                hook(path);
            }
        }
    }

    fn descriptor() -> ResolvedUpdate {
        ResolvedUpdate {
            version: "0.4.1".into(),
            target: "test".into(),
            artifact_url: "https://nelomai.ru/artifact".into(),
            signature: "signature".into(),
            key_identity: "key".into(),
            sha256: None,
            size_bytes: Some(11),
        }
    }

    fn partial_fixture() -> (tempfile::TempDir, PreparedCache, ResolvedUpdate) {
        let root = tempfile::tempdir().unwrap();
        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        let descriptor = descriptor();
        let validator =
            DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
        let mut file = cache.begin().unwrap();
        file.write_all(b"hello").unwrap();
        cache.save_partial(file, &descriptor, &validator).unwrap();
        (root, cache, descriptor)
    }

    fn replace_at_move(root: &Path, name: &str, replacement: Vec<u8>) {
        let original = root.join("admitted");
        BEFORE_MOVE.set(Some((
            name.to_owned(),
            Box::new(move |source| {
                fs::rename(source, original).unwrap();
                fs::write(source, replacement).unwrap();
            }),
        )));
    }

    #[test]
    fn verified_publication_refuses_a_source_replaced_at_the_move_boundary() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("packages");
        let cache = PreparedCache::open(path.clone()).unwrap();
        let descriptor = descriptor();
        let key = descriptor.cache_key().unwrap();
        let mut staged = cache.begin().unwrap();
        staged.write_all(b"hello world").unwrap();
        let source = staged.path().to_owned();
        replace_at_move(
            root.path(),
            source.file_name().unwrap().to_str().unwrap(),
            b"foreign staging".to_vec(),
        );

        assert!(cache
            .commit_verified(staged, descriptor, HELLO_WORLD_SHA256)
            .is_err());
        assert!(!path.join(format!("package-{key}.bin")).exists());
        assert!(!path.join(format!("package-{key}.json")).exists());
        assert_eq!(fs::read(source).unwrap(), b"foreign staging");
        assert_eq!(
            fs::read(root.path().join("admitted")).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn verified_publication_collision_restores_only_a_vacant_staging_name() {
        for reoccupied in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("packages");
            let cache = PreparedCache::open(path.clone()).unwrap();
            let descriptor = descriptor();
            let key = descriptor.cache_key().unwrap();
            let destination = path.join(format!("package-{key}.bin"));
            let mut staged = cache.begin().unwrap();
            staged.write_all(b"hello world").unwrap();
            let source = staged.path().to_owned();
            let collision = destination.clone();
            AFTER_MOVE.set(Some((
                source.file_name().unwrap().to_str().unwrap().into(),
                Box::new(move |source| {
                    fs::write(collision, b"foreign canonical").unwrap();
                    if reoccupied {
                        fs::write(source, b"foreign staging").unwrap();
                    }
                }),
            )));

            let result = cache.commit_verified(staged, descriptor, HELLO_WORLD_SHA256);
            assert_eq!(fs::read(&destination).unwrap(), b"foreign canonical");
            assert!(!path.join(format!("package-{key}.json")).exists());
            if reoccupied {
                assert!(result.is_err());
                assert_eq!(fs::read(source).unwrap(), b"foreign staging");
                let isolated = fs::read_dir(&path)
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| name.starts_with(CLAIM_PREFIX))
                    })
                    .unwrap();
                assert_eq!(
                    fs::read(isolated.path().join(CLAIM_ENTRY)).unwrap(),
                    b"hello world"
                );
            } else {
                let prepared = result.unwrap();
                assert_eq!(prepared.path(), source);
                assert_eq!(fs::read(&source).unwrap(), b"hello world");
                drop(prepared);
                assert!(!source.exists());
            }
        }
    }

    #[test]
    fn finish_preserves_a_replacement_at_the_move_boundary() {
        let (root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" world").unwrap();
        replace_at_move(root.path(), PARTIAL_DATA, b"replacement".to_vec());

        assert!(cache.finish_resume(resumed).is_err());
        assert_eq!(
            fs::read(cache.root.join(PARTIAL_DATA)).unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn finish_preserves_an_occupant_arriving_after_the_source_is_claimed() {
        use std::rc::Rc;

        let (_root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" world").unwrap();
        let occupied = Rc::new(RefCell::new(None));
        let observe = occupied.clone();
        AFTER_MOVE.set(Some((
            PARTIAL_DATA.into(),
            Box::new(move |source| {
                let directory = source.parent().unwrap();
                let marker = fs::read_dir(directory)
                    .unwrap()
                    .flatten()
                    .find_map(|entry| {
                        let name = entry.file_name();
                        let name = name.to_str()?;
                        let staging = super::super::staging_record_target(name)?;
                        staging
                            .starts_with(".package-")
                            .then(|| directory.join(staging))
                    })
                    .unwrap();
                if marker.exists() {
                    fs::remove_file(&marker).unwrap();
                }
                fs::write(&marker, b"foreign staging").unwrap();
                observe.replace(Some(marker));
            }),
        )));

        assert!(cache.finish_resume(resumed).is_err());
        assert_eq!(
            fs::read(occupied.take().unwrap()).unwrap(),
            b"foreign staging"
        );
        assert_eq!(
            fs::read(cache.root.join(PARTIAL_DATA)).unwrap(),
            b"hello world"
        );
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_only_recovery_finishes_an_interrupted_staging_claim() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("packages");
        let cache = PreparedCache::open(path.clone()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut staged = cache.begin().unwrap();
        staged.write_all(b"abandoned").unwrap();
        let (file, staged_path) = staged.keep().unwrap();
        let claimed = cache.claim_cache_entry(&staged_path, &file, true).unwrap();
        drop((claimed, file, cache));

        let cache = PreparedCache::open(path).unwrap();
        cache.recover("0.4.0").unwrap();
        assert_eq!(fs::read_dir(&cache.root).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn verified_temporary_lease_without_birth_time_releases_only_its_own_entry() {
        struct RestoreBirthTime;
        impl Drop for RestoreBirthTime {
            fn drop(&mut self) {
                OMIT_BIRTH_TIME.set(false);
            }
        }
        OMIT_BIRTH_TIME.set(true);
        let _restore = RestoreBirthTime;
        for replaced in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let cache = PreparedCache::open(root.path().join("packages")).unwrap();
            let mut file = cache.begin().unwrap();
            file.write_all(b"hello world").unwrap();
            let prepared = cache
                .commit_verified(file, descriptor(), HELLO_WORLD_SHA256)
                .unwrap();
            let staging = prepared.path().to_owned();
            assert!(cache.cached_path(prepared.resolved()).unwrap().is_none());
            assert_eq!(fs::read(&staging).unwrap(), b"hello world");
            if replaced {
                fs::rename(&staging, root.path().join("original")).unwrap();
                fs::write(&staging, b"foreign").unwrap();
            }
            drop(prepared);
            if replaced {
                assert_eq!(fs::read(staging).unwrap(), b"foreign");
                assert_eq!(
                    fs::read(root.path().join("original")).unwrap(),
                    b"hello world"
                );
            } else {
                assert!(!staging.exists());
            }
        }
    }

    #[test]
    fn discard_preserves_both_replacements_when_the_original_name_is_occupied() {
        let (root, cache, descriptor) = partial_fixture();
        let saved = cache.partial(&descriptor).unwrap().unwrap();
        replace_at_move(root.path(), PARTIAL_DATA, b"first replacement".to_vec());
        AFTER_MOVE.set(Some((
            PARTIAL_DATA.into(),
            Box::new(|path| {
                fs::write(path, b"second replacement").unwrap();
            }),
        )));

        assert!(cache.discard_admitted_partial(saved).is_err());
        cache.recover(&descriptor.version).unwrap();
        assert_eq!(
            fs::read(cache.root.join(PARTIAL_DATA)).unwrap(),
            b"second replacement"
        );
        let protected = fs::read_dir(&cache.root)
            .unwrap()
            .flatten()
            .find(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(CLAIM_PREFIX))
            })
            .unwrap();
        assert_eq!(
            fs::read(protected.path().join(CLAIM_ENTRY)).unwrap(),
            b"first replacement"
        );
    }

    #[test]
    fn restart_discards_claimed_partial_data_after_cleanup_was_interrupted() {
        let (root, cache, descriptor) = partial_fixture();
        let saved = cache.partial(&descriptor).unwrap().unwrap();
        FAIL_REMOVE.set(Some(PARTIAL_DATA));
        assert!(cache.discard_admitted_partial(saved).is_err());
        assert!(!cache.root.join(PARTIAL_METADATA).exists());
        assert!(!cache.root.join(PARTIAL_DATA).exists());
        drop(cache);

        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        cache.recover("0.4.0").unwrap();
        assert!(!cache.root.join(PARTIAL_DATA).exists());
        let validator = DownloadValidator::new(&descriptor.artifact_url, "\"new\"", 11).unwrap();
        let mut file = cache.begin().unwrap();
        file.write_all(b"next").unwrap();
        cache.save_partial(file, &descriptor, &validator).unwrap();
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 4);
    }

    #[test]
    fn checkpoint_preserves_a_sidecar_replaced_at_the_move_boundary() {
        let (root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" wo").unwrap();
        let path = cache.root.join(PARTIAL_METADATA);
        let replacement = fs::read(&path).unwrap();
        replace_at_move(root.path(), PARTIAL_METADATA, replacement.clone());

        assert!(cache.checkpoint_resume(resumed).is_err());
        cache.recover(&descriptor.version).unwrap();
        assert_eq!(fs::read(path).unwrap(), replacement);
        assert!(cache.partial(&descriptor).unwrap().is_none());
    }

    #[test]
    fn startup_restores_an_owned_checkpoint_interrupted_during_its_move() {
        let (_root, cache, descriptor) = partial_fixture();
        let saved = cache.partial(&descriptor).unwrap().unwrap();
        let path = cache.root.join(PARTIAL_METADATA);
        let claimed = cache.claim_sidecar(&saved).unwrap();
        assert!(!path.exists());
        drop((claimed, saved));

        cache.recover("0.4.0").unwrap();
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 5);
        cache.recover(&descriptor.version).unwrap();
        assert!(!cache.root.join(PARTIAL_DATA).exists());
        assert!(!path.exists());
    }

    #[test]
    fn startup_preserves_a_checkpoint_claim_until_the_foreign_sidecar_is_gone() {
        let (root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" wo").unwrap();
        let sidecar = cache.root.join(PARTIAL_METADATA);
        let replacement = fs::read(&sidecar).unwrap();
        let occupant = replacement.clone();
        AFTER_MOVE.set(Some((
            PARTIAL_METADATA.into(),
            Box::new(move |path| fs::write(path, occupant).unwrap()),
        )));
        assert!(cache.checkpoint_resume(resumed).is_err());
        drop(cache);

        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        cache.recover("0.4.0").unwrap();
        assert_eq!(fs::read(&sidecar).unwrap(), replacement);
        assert!(cache.partial(&descriptor).unwrap().is_none());

        fs::remove_file(&sidecar).unwrap();
        cache.recover("0.4.0").unwrap();
        let saved = cache.partial(&descriptor).unwrap().unwrap();
        assert_eq!(saved.received(), 5);
        let mut resumed = cache.begin_resume(saved).unwrap();
        resumed.write_all(b" world").unwrap();
        let complete = cache.finish_resume(resumed).unwrap();
        assert_eq!(fs::read(complete.path()).unwrap(), b"hello world");
    }

    #[test]
    fn startup_retires_an_old_checkpoint_claim_after_its_successor_was_published() {
        let (root, cache, descriptor, old_claim) = published_checkpoint_with_old_claim();
        drop(cache);

        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        cache.recover("0.4.0").unwrap();
        assert!(!old_claim.exists());
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 8);
    }

    fn published_checkpoint_with_old_claim(
    ) -> (tempfile::TempDir, PreparedCache, ResolvedUpdate, PathBuf) {
        let (root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" wo").unwrap();
        FAIL_REMOVE.set(Some(PARTIAL_METADATA));
        assert!(cache.checkpoint_resume(resumed).is_err());
        let old_claim = fs::read_dir(&cache.root)
            .unwrap()
            .flatten()
            .find(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(CLAIM_PREFIX))
            })
            .unwrap()
            .path();
        assert!(old_claim.join(CLAIM_ENTRY).is_file());
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 8);
        (root, cache, descriptor, old_claim)
    }

    #[test]
    fn startup_restores_the_newest_owned_checkpoint_in_either_claim_order() {
        for newest_first in [false, true] {
            let (root, cache, descriptor, old_claim) = published_checkpoint_with_old_claim();
            let mut resumed = cache
                .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
                .unwrap();
            resumed.write_all(b"r").unwrap();
            let new_claim = cache.claim_sidecar(&resumed.saved).unwrap();
            let directories = if newest_first {
                [new_claim.directory, old_claim.clone()]
            } else {
                [old_claim.clone(), new_claim.directory]
            };
            assert!(!cache.root.join(PARTIAL_METADATA).exists());
            drop((resumed, cache));

            let cache = PreparedCache::open(root.path().join("packages")).unwrap();
            cache.recover_claims(directories, true);
            cache.recover("0.4.0").unwrap();
            let saved = cache.partial(&descriptor).unwrap().unwrap();
            assert_eq!(saved.received(), 8);
            assert!(!old_claim.exists());
            let mut resumed = cache.begin_resume(saved).unwrap();
            resumed.write_all(b"rld").unwrap();
            let complete = cache.finish_resume(resumed).unwrap();
            assert_eq!(fs::read(complete.path()).unwrap(), b"hello world");
        }
    }

    #[test]
    fn startup_ranks_claims_for_the_current_checkpoint_data() {
        let (root, cache, descriptor) = partial_fixture();
        let old = cache.partial(&descriptor).unwrap().unwrap();
        let old_claim = cache.claim_sidecar(&old).unwrap();
        fs::rename(&old.path, root.path().join("previous-data")).unwrap();
        drop(old);

        let validator =
            DownloadValidator::new(&descriptor.artifact_url, "\"fixture\"", 11).unwrap();
        let mut staged = cache.begin().unwrap();
        staged.write_all(b"hell").unwrap();
        cache.save_partial(staged, &descriptor, &validator).unwrap();
        let current = cache.partial(&descriptor).unwrap().unwrap();
        let current_claim = cache.claim_sidecar(&current).unwrap();
        drop(current);

        cache.recover_claims([old_claim.directory.clone(), current_claim.directory], true);
        assert_eq!(cache.partial(&descriptor).unwrap().unwrap().received(), 4);
        assert!(old_claim.entry().is_file());
    }

    #[test]
    fn startup_preserves_checkpoint_data_behind_a_foreign_occupant() {
        resume_after_data_claim_collision(false);
    }

    #[test]
    fn startup_preserves_the_sidecar_when_the_occupant_leaves_during_recovery() {
        resume_after_data_claim_collision(true);
    }

    fn resume_after_data_claim_collision(vacate_during_recovery: bool) {
        let (root, cache, descriptor) = partial_fixture();
        let mut resumed = cache
            .begin_resume(cache.partial(&descriptor).unwrap().unwrap())
            .unwrap();
        resumed.write_all(b" world").unwrap();
        // Stop at the point where finish_resume has claimed the completed data.
        let data_path = resumed.saved.path.clone();
        let claim = cache.claim_entry(&data_path, &resumed.saved.file).unwrap();
        let sidecar = cache.root.join(PARTIAL_METADATA);
        let checkpoint = fs::read(&sidecar).unwrap();
        assert!(!data_path.exists());
        fs::write(&data_path, b"foreign data").unwrap();
        drop((claim, resumed, cache));

        let cache = PreparedCache::open(root.path().join("packages")).unwrap();
        if vacate_during_recovery {
            AFTER_CLAIM_RECOVERY.set(Some((
                PARTIAL_DATA.into(),
                Box::new(|path| fs::remove_file(path).unwrap()),
            )));
        }
        cache.recover("0.4.0").unwrap();
        assert_eq!(fs::read(&sidecar).unwrap(), checkpoint);
        assert!(cache.partial(&descriptor).unwrap().is_none());
        if !vacate_during_recovery {
            assert_eq!(fs::read(&data_path).unwrap(), b"foreign data");
            fs::remove_file(&data_path).unwrap();
        }

        cache.recover("0.4.0").unwrap();
        let saved = cache.partial(&descriptor).unwrap().unwrap();
        assert_eq!(saved.received(), 5);
        let mut resumed = cache.begin_resume(saved).unwrap();
        resumed.write_all(b" world").unwrap();
        let complete = cache.finish_resume(resumed).unwrap();
        assert_eq!(fs::read(complete.path()).unwrap(), b"hello world");
    }
}
