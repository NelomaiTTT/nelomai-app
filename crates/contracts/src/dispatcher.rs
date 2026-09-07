//! Stable privileged lifecycle and verified installation transaction. Product
//! tunnel requests remain opaque frames handled by the versioned engine.
use crate::{verify_container_manifest, RuntimeFileRole, RuntimeSlot, VerifiedContainerManifest};
use base64::Engine;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MANIFEST_NAME: &str = "container-manifest-v1.json";
pub const SIGNATURE_NAME: &str = "container-manifest-v1.sig";
/// A root-owned atomic pointer containing the immutable generation basename.
pub const POINTER_NAME: &str = "container-manifest.json";
pub const ACTIVE_ENGINE_NAME: &str = "engine-active";
pub const MAX_DISPATCHER_FRAME: usize = 4096;
pub const MAX_ENGINE_FRAME: usize = 1024 * 1024;
const POLICY_NAME: &str = "installation-policy.json";

pub fn blocked() -> io::Error {
    io::Error::other("dispatcher_identity_or_state_rejected")
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn pinned_key() -> io::Result<[u8; 32]> {
    let value = option_env!("NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64").ok_or_else(blocked)?;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| blocked())?
        .try_into()
        .map_err(|_| blocked())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineIdentity {
    pub slot: RuntimeSlot,
    pub runtime_version: String,
    pub runtime_contract_version: u32,
    pub container_version: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatcherRequest {
    Start {
        contract_version: u32,
        identity: EngineIdentity,
    },
    Stop {
        contract_version: u32,
        identity: EngineIdentity,
    },
    Cleanup {
        contract_version: u32,
        identity: EngineIdentity,
    },
    Status {
        contract_version: u32,
    },
    Version {
        contract_version: u32,
    },
}
impl DispatcherRequest {
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::Start { .. } | Self::Stop { .. } | Self::Cleanup { .. }
        )
    }
    pub fn identity(&self) -> Option<&EngineIdentity> {
        match self {
            Self::Start { identity, .. }
            | Self::Stop { identity, .. }
            | Self::Cleanup { identity, .. } => Some(identity),
            _ => None,
        }
    }
    fn contract(&self) -> u32 {
        match self {
            Self::Start {
                contract_version, ..
            }
            | Self::Stop {
                contract_version, ..
            }
            | Self::Cleanup {
                contract_version, ..
            }
            | Self::Status { contract_version }
            | Self::Version { contract_version } => *contract_version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatcherResponse {
    pub contract_version: u32,
    pub ok: bool,
    pub identity: Option<EngineIdentity>,
    pub running: bool,
    pub error: Option<String>,
}
impl DispatcherResponse {
    pub fn success(identity: EngineIdentity, running: bool) -> Self {
        Self {
            contract_version: 1,
            ok: true,
            identity: Some(identity),
            running,
            error: None,
        }
    }
    pub fn failure() -> Self {
        Self {
            contract_version: 1,
            ok: false,
            identity: None,
            running: false,
            error: Some("dispatcher_rejected".into()),
        }
    }
}
pub fn encode_frame(value: &impl Serialize) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(value).map_err(|_| blocked())?;
    if body.len() > MAX_ENGINE_FRAME {
        return Err(blocked());
    }
    let mut frame = (body.len() as u32).to_le_bytes().to_vec();
    frame.extend(body);
    Ok(frame)
}
pub fn decode_request(frame: &[u8]) -> io::Result<DispatcherRequest> {
    let body = frame_body(frame, MAX_DISPATCHER_FRAME)?;
    let request: DispatcherRequest = serde_json::from_slice(body).map_err(|_| blocked())?;
    if request.contract() != 1 {
        return Err(blocked());
    }
    Ok(request)
}
pub fn frame_body(frame: &[u8], limit: usize) -> io::Result<&[u8]> {
    if frame.len() < 4 || frame.len() > limit + 4 {
        return Err(blocked());
    }
    let size = u32::from_le_bytes(frame[..4].try_into().map_err(|_| blocked())?) as usize;
    if size + 4 != frame.len() {
        return Err(blocked());
    }
    Ok(&frame[4..])
}
pub fn read_frame(reader: &mut impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let n = u32::from_le_bytes(size) as usize;
    if n > limit {
        return Err(blocked());
    }
    let mut frame = size.to_vec();
    frame.resize(n + 4, 0);
    reader.read_exact(&mut frame[4..])?;
    Ok(frame)
}
pub fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    open_regular(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > limit {
        return Err(blocked());
    }
    Ok(data)
}
pub fn file_digest(path: &Path) -> io::Result<String> {
    let mut file = open_regular(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPolicy {
    pub owner: String,
    pub executable: PathBuf,
    pub sha256: String,
    pub manifest_sha256: String,
}
impl BrokerPolicy {
    pub fn authorize(&self, owner: &str, kernel_executable: &Path) -> io::Result<()> {
        // Never canonicalize an untrusted peer path into an allowed alias.
        if owner != self.owner
            || kernel_executable != self.executable
            || file_digest(kernel_executable)? != self.sha256
        {
            return Err(blocked());
        }
        Ok(())
    }
}

/// The file is held for the entire operation, including private-engine IPC.
pub struct MutationGuard(File);
impl MutationGuard {
    pub fn acquire(root: &Path) -> io::Result<Self> {
        Self::at(&root.join("mutation.lock"))
    }
    pub fn at(path: &Path) -> io::Result<Self> {
        if path.exists() {
            reject_link(path)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(blocked());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.try_lock_exclusive()?;
        Ok(Self(file))
    }
}
impl Drop for MutationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

pub trait InstallIo {
    fn copy(&self, source: &Path, destination: &Path) -> io::Result<()>;
    fn publish(&self, source: &Path, destination: &Path) -> io::Result<()>;
}
pub struct RealInstallIo;
impl InstallIo for RealInstallIo {
    fn copy(&self, source: &Path, destination: &Path) -> io::Result<()> {
        let mut source = open_regular(source)?;
        let mut destination = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?;
        io::copy(&mut source, &mut destination)?;
        destination.sync_all()
    }
    fn publish(&self, source: &Path, destination: &Path) -> io::Result<()> {
        atomic_replace(source, destination)
    }
}
pub fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)?;
        File::open(destination.parent().ok_or_else(blocked)?)?.sync_all()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let destination: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(blocked());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(blocked());
        }
    }
    Ok(file)
}

fn reject_link(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(blocked());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(blocked());
        }
    }
    Ok(metadata)
}
pub fn trusted(path: &Path, owner: u32) -> io::Result<()> {
    let metadata = reject_link(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != owner || metadata.permissions().mode() & 0o022 != 0 {
            return Err(blocked());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (metadata, owner);
    }
    Ok(())
}
fn protect(path: &Path, executable: bool) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o600 }),
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

#[derive(Clone)]
pub struct Installation {
    pub root: PathBuf,
    key: [u8; 32],
    platform: String,
    architecture: String,
    owner: u32,
    strict_ancestors: bool,
}
pub struct VerifiedLayout {
    pub directory: PathBuf,
    pub identity: EngineIdentity,
    pub broker: BrokerPolicy,
    engine: PathBuf,
}
impl VerifiedLayout {
    pub fn engine_path(&self) -> PathBuf {
        self.engine.clone()
    }
    pub fn dispatcher_path(&self) -> PathBuf {
        self.directory
            .join("dispatcher/1")
            .join(self.engine.file_name().expect("verified engine filename"))
    }
    pub fn authorize(&self, identity: &EngineIdentity) -> io::Result<()> {
        if identity != &self.identity {
            Err(blocked())
        } else {
            Ok(())
        }
    }
}
impl Installation {
    pub fn production(root: &Path) -> io::Result<Self> {
        let mut installation = Self::for_owner(
            root,
            pinned_key()?,
            std::env::consts::OS,
            std::env::consts::ARCH,
            0,
        );
        installation.strict_ancestors = true;
        Ok(installation)
    }
    /// Explicit trust/ownership injection used by owned test fixtures, never CLI input.
    pub fn for_owner(
        root: &Path,
        key: [u8; 32],
        platform: &str,
        architecture: &str,
        owner: u32,
    ) -> Self {
        Self {
            root: root.into(),
            key,
            platform: platform.into(),
            architecture: architecture.into(),
            owner,
            strict_ancestors: false,
        }
    }
    fn engine_name(&self) -> &'static str {
        if self.platform == "windows" {
            "nelomai-windows-service.exe"
        } else {
            "nelomai-unix-service"
        }
    }
    pub fn manifest_identity(&self, directory: &Path) -> io::Result<EngineIdentity> {
        let (verified, manifest_sha256) = self.verified_manifest(directory)?;
        Ok(EngineIdentity {
            slot: RuntimeSlot::Latest,
            runtime_version: verified.latest().runtime_version.clone(),
            runtime_contract_version: verified.latest().contract_version,
            container_version: verified.manifest().container_version.clone(),
            manifest_sha256,
        })
    }
    fn verified_manifest(
        &self,
        directory: &Path,
    ) -> io::Result<(VerifiedContainerManifest, String)> {
        let bytes = read_bounded(&directory.join(MANIFEST_NAME), 1024 * 1024)?;
        let sig = read_bounded(&directory.join(SIGNATURE_NAME), 64)?;
        let verified =
            verify_container_manifest(&bytes, &sig, &self.key, &self.platform, &self.architecture)
                .map_err(|_| blocked())?;
        Ok((verified, digest(&bytes)))
    }
    fn verify_files(
        &self,
        directory: &Path,
        verified: &VerifiedContainerManifest,
    ) -> io::Result<PathBuf> {
        let mut selected_engine = None;
        for slot in &verified.manifest().slots {
            let name = match slot.slot {
                RuntimeSlot::Latest => "latest",
                RuntimeSlot::Stable => "stable",
            };
            let relative_root = PathBuf::from("engines")
                .join(name)
                .join(&slot.manifest.runtime_version);
            for entry in &slot.manifest.files {
                let relative = relative_root.join(&entry.path);
                let mut cursor = directory.to_path_buf();
                for component in relative.components() {
                    cursor.push(component);
                    trusted(&cursor, self.owner)?;
                }
                let metadata = reject_link(&cursor)?;
                if !metadata.is_file()
                    || metadata.len() != entry.size_bytes
                    || file_digest(&cursor)? != entry.sha256
                {
                    return Err(blocked());
                }
                if slot.slot == RuntimeSlot::Latest
                    && entry.path == self.engine_name()
                    && entry.role == RuntimeFileRole::Executable
                {
                    selected_engine = Some(cursor);
                }
            }
        }
        selected_engine.ok_or_else(blocked)
    }
    pub fn load(&self) -> io::Result<VerifiedLayout> {
        self.trusted_ancestors(&self.root)?;
        trusted(&self.root, self.owner)?;
        trusted(&self.root.join(POINTER_NAME), self.owner)?;
        let pointer = String::from_utf8(read_bounded(&self.root.join(POINTER_NAME), 96)?)
            .map_err(|_| blocked())?;
        if !valid_generation(&pointer) {
            return Err(blocked());
        }
        let directory = self.root.join("releases").join(pointer);
        trusted(&self.root.join("releases"), self.owner)?;
        trusted(&directory, self.owner)?;
        for name in [MANIFEST_NAME, SIGNATURE_NAME, POLICY_NAME] {
            trusted(&directory.join(name), self.owner)?;
        }
        let (verified, hash) = self.verified_manifest(&directory)?;
        let engine = self.verify_files(&directory, &verified)?;
        let broker: BrokerPolicy =
            serde_json::from_slice(&read_bounded(&directory.join(POLICY_NAME), 8192)?)
                .map_err(|_| blocked())?;
        if broker.manifest_sha256 != hash || !broker.executable.is_absolute() {
            return Err(blocked());
        }
        trusted(&broker.executable, self.owner)?;
        self.trusted_ancestors(&broker.executable)?;
        if file_digest(&broker.executable)? != broker.sha256 {
            return Err(blocked());
        }
        let latest = verified.latest();
        Ok(VerifiedLayout {
            directory,
            engine,
            broker,
            identity: EngineIdentity {
                slot: RuntimeSlot::Latest,
                runtime_version: latest.runtime_version.clone(),
                runtime_contract_version: latest.contract_version,
                container_version: verified.manifest().container_version.clone(),
                manifest_sha256: hash,
            },
        })
    }
    pub fn install(
        &self,
        source: &Path,
        broker: &Path,
        owner: &str,
        operations: &impl InstallIo,
    ) -> io::Result<VerifiedLayout> {
        if self.root.exists() {
            trusted(&self.root, self.owner)?;
        }
        if let Some(parent) = self.root.parent() {
            self.trusted_ancestors(parent)?;
        }
        fs::create_dir_all(&self.root)?;
        protect(&self.root, true)?;
        trusted(&self.root, self.owner)?;
        let _guard = MutationGuard::acquire(&self.root)?;
        if self.root.join(ACTIVE_ENGINE_NAME).exists() {
            return Err(blocked());
        }
        let broker = fs::canonicalize(broker)?;
        trusted(&broker, self.owner)?;
        self.trusted_ancestors(&self.root)?;
        self.trusted_ancestors(&broker)?;
        if owner.is_empty() || owner.len() > 256 {
            return Err(blocked());
        }
        let (manifest, hash) = self.verified_manifest(source)?;
        // Platform copy hooks may prepare narrowly scoped OS resources. Never
        // run them for payload bytes that already fail their signed index.
        self.verify_files(source, &manifest)?;
        let generation = format!(
            "{}-{:x}",
            hash,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| blocked())?
                .as_nanos()
        );
        let releases = self.root.join("releases");
        fs::create_dir_all(&releases)?;
        protect(&releases, true)?;
        let stage = releases.join(format!(".stage-{generation}"));
        fs::create_dir(&stage)?;
        protect(&stage, false)?;
        // Directories need search permission; keep staging private until complete.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
        }
        let pointer_temp = self.root.join(format!(".pointer-{generation}"));
        let previous_pointer = match read_bounded(&self.root.join(POINTER_NAME), 96) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let result = (|| {
            for name in [MANIFEST_NAME, SIGNATURE_NAME] {
                operations.copy(&source.join(name), &stage.join(name))?;
                protect(&stage.join(name), false)?;
            }
            for slot in &manifest.manifest().slots {
                let slot_name = match slot.slot {
                    RuntimeSlot::Latest => "latest",
                    RuntimeSlot::Stable => "stable",
                };
                for entry in &slot.manifest.files {
                    let path = PathBuf::from("engines")
                        .join(slot_name)
                        .join(&slot.manifest.runtime_version)
                        .join(&entry.path);
                    let destination = stage.join(&path);
                    fs::create_dir_all(destination.parent().ok_or_else(blocked)?)?;
                    operations.copy(&source.join(&path), &destination)?;
                    protect(&destination, entry.role == RuntimeFileRole::Executable)?;
                }
            }
            let (copied_manifest, copied_hash) = self.verified_manifest(&stage)?;
            if copied_hash != hash {
                return Err(blocked());
            }
            let engine = self.verify_files(&stage, &copied_manifest)?;
            let dispatcher_dir = stage.join("dispatcher/1");
            fs::create_dir_all(&dispatcher_dir)?;
            let dispatcher_path = dispatcher_dir.join(self.engine_name());
            operations.copy(&engine, &dispatcher_path)?;
            protect(&dispatcher_path, true)?;
            if file_digest(&dispatcher_path)? != file_digest(&engine)? {
                return Err(blocked());
            }
            let policy = BrokerPolicy {
                owner: owner.into(),
                sha256: file_digest(&broker)?,
                executable: broker,
                manifest_sha256: hash,
            };
            write_new(
                &stage.join(POLICY_NAME),
                &serde_json::to_vec(&policy).map_err(|_| blocked())?,
            )?;
            let committed = releases.join(&generation);
            sync_directories(&stage)?;
            fs::rename(&stage, &committed)?;
            sync_directory(&releases)?;
            write_new(&pointer_temp, generation.as_bytes())?;
            let publication = operations
                .publish(&pointer_temp, &self.root.join(POINTER_NAME))
                .and_then(|_| self.load());
            if publication.is_err() {
                if let Some(previous) = &previous_pointer {
                    let rollback = self.root.join(format!(".rollback-{generation}"));
                    write_new(&rollback, previous)?;
                    atomic_replace(&rollback, &self.root.join(POINTER_NAME))?;
                } else if self.root.join(POINTER_NAME).exists() {
                    fs::remove_file(self.root.join(POINTER_NAME))?;
                    sync_directory(&self.root)?;
                }
            }
            publication
        })();
        if stage.exists() {
            let _ = fs::remove_dir_all(&stage);
        }
        if pointer_temp.exists() {
            let _ = fs::remove_file(&pointer_temp);
        }
        // Unreferenced committed generations are recoverable, never the old root.
        result
    }
    fn cleanup_previous(&self) -> io::Result<()> {
        if self.root.join(ACTIVE_ENGINE_NAME).exists() {
            return Err(blocked());
        }
        let _lease = MutationGuard::at(&self.root.join("engine-owner.lock"))?;
        let current = String::from_utf8(read_bounded(&self.root.join(POINTER_NAME), 96)?)
            .map_err(|_| blocked())?;
        if !valid_generation(&current) {
            return Err(blocked());
        }
        let dispatcher = fs::canonicalize(std::env::current_exe()?)?;
        let releases = self.root.join("releases");
        trusted(&releases, self.owner)?;
        // Bounded, conservative collection. Unknown/unverified contents and the
        // running dispatcher's own generation are never removed.
        for entry in fs::read_dir(&releases)?.take(64) {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !valid_generation(&name) || name == current {
                continue;
            }
            let path = entry.path();
            if trusted(&path, self.owner).is_err() || !entry.file_type()?.is_dir() {
                continue;
            }
            if dispatcher.starts_with(fs::canonicalize(&path)?) {
                continue;
            }
            let Ok((manifest, _)) = self.verified_manifest(&path) else {
                continue;
            };
            if self.verify_files(&path, &manifest).is_err() {
                continue;
            }
            fs::remove_dir_all(&path)?;
        }
        sync_directory(&releases)
    }

    fn trusted_ancestors(&self, path: &Path) -> io::Result<()> {
        #[cfg(not(unix))]
        let _ = path;
        if self.strict_ancestors {
            #[cfg(unix)]
            for ancestor in path.ancestors() {
                trusted(ancestor, 0)?;
            }
        }
        Ok(())
    }

    /// Platform activation may fail after publication. Restore only the exact
    /// expected generation, under the same mutation lock, with no active engine.
    pub fn rollback_activation(&self, published: &str, previous: Option<&str>) -> io::Result<()> {
        let _guard = MutationGuard::acquire(&self.root)?;
        if self.root.join(ACTIVE_ENGINE_NAME).exists()
            || !valid_generation(published)
            || read_bounded(&self.root.join(POINTER_NAME), 96)? != published.as_bytes()
        {
            return Err(blocked());
        }
        if let Some(previous) = previous {
            if !valid_generation(previous) {
                return Err(blocked());
            }
            let directory = self.root.join("releases").join(previous);
            trusted(&directory, self.owner)?;
            let (manifest, _) = self.verified_manifest(&directory)?;
            self.verify_files(&directory, &manifest)?;
            let temporary = self.root.join(format!(".activation-rollback-{published}"));
            write_new(&temporary, previous.as_bytes())?;
            atomic_replace(&temporary, &self.root.join(POINTER_NAME))
        } else {
            fs::remove_file(self.root.join(POINTER_NAME))?;
            sync_directory(&self.root)
        }
    }
}
fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn sync_directories(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    sync_directory(path)
}
fn valid_generation(value: &str) -> bool {
    value.len() > 65
        && value.len() <= 96
        && value.as_bytes()[64] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 64 || b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    protect(path, false)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePrimitive {
    StartWireguard,
    StartAmneziawg,
    StopServices,
    RebindService,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrimitiveRequest {
    pub engine_primitive: EnginePrimitive,
}

/// The guardian shares only the new engine's process group and a kernel pipe.
/// Closing the dispatcher's non-inherited endpoint (including SIGKILL/exit)
/// kills that group even if the engine is stuck and cannot observe stdio EOF.
/// A successful daemon-launch command may write one byte to disarm its
/// transient guardian; persisted tunnel state then owns daemon recovery.
#[cfg(unix)]
pub fn own_process_group(
    command: &mut std::process::Command,
) -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    let (owner, guardian) = std::os::unix::net::UnixStream::pair()?;
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.max(1024);
    unsafe {
        command.pre_exec(move || {
            let read_fd = guardian.as_raw_fd();
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            match libc::fork() {
                -1 => return Err(io::Error::last_os_error()),
                0 => {
                    // Async-signal-safe only after fork. Do not inherit locks,
                    // stdio or another tree's pipe endpoints into the guardian.
                    if libc::dup2(read_fd, 3) < 0 {
                        libc::_exit(127);
                    }
                    libc::close(0);
                    libc::close(1);
                    libc::close(2);
                    for fd in 4..max_fd {
                        libc::close(fd as libc::c_int);
                    }
                    let mut byte = 0u8;
                    loop {
                        let result = libc::read(3, (&mut byte as *mut u8).cast(), 1);
                        if result == 0 {
                            break;
                        }
                        if result > 0 {
                            libc::_exit(0);
                        }
                        if result < 0
                            && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                        {
                            break;
                        }
                    }
                    libc::kill(0, libc::SIGKILL);
                    libc::_exit(127);
                }
                _ => {}
            }
            Ok(())
        });
    }
    Ok(owner)
}

#[cfg(windows)]
fn own_dispatcher_job() -> io::Result<()> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError},
        System::{JobObjects::*, Threading::GetCurrentProcess},
    };
    // Deliberately process-lifetime, non-inheritable handle. Assigning the
    // dispatcher before spawn closes the child-creation/assignment race; all
    // descendants inherit containment, not the handle that keeps it alive.
    static JOB: std::sync::OnceLock<Result<usize, u32>> = std::sync::OnceLock::new();
    let result = JOB.get_or_init(|| unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(GetLastError());
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        ) == 0
            || AssignProcessToJobObject(job, GetCurrentProcess()) == 0
        {
            let error = GetLastError();
            CloseHandle(job);
            return Err(error);
        }
        Ok(job as usize)
    });
    result
        .as_ref()
        .map(|_| ())
        .map_err(|error| io::Error::from_raw_os_error(*error as i32))
}

/// Both privileged endpoints share this owner. Private product frames are
/// forwarded unchanged. Only the inherited engine channel can request an SCM
/// primitive; the common broker cannot send those responses to the dispatcher.
pub struct ProcessDispatcher {
    pub installation: Installation,
    pub layout: VerifiedLayout,
    child: Option<std::process::Child>,
    #[cfg(unix)]
    tree_owner: Option<std::os::unix::net::UnixStream>,
    channel_failed: bool,
}
impl ProcessDispatcher {
    pub fn new(installation: Installation) -> io::Result<Self> {
        let layout = installation.load()?;
        Ok(Self {
            installation,
            layout,
            child: None,
            #[cfg(unix)]
            tree_owner: None,
            channel_failed: false,
        })
    }
    pub fn handle(
        &mut self,
        request: DispatcherRequest,
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> DispatcherResponse {
        match self.handle_inner(request, primitive) {
            Ok(()) => {
                let running = !self.channel_failed
                    && self
                        .child
                        .as_mut()
                        .is_some_and(|child| matches!(child.try_wait(), Ok(None)));
                DispatcherResponse::success(self.layout.identity.clone(), running)
            }
            Err(_) => DispatcherResponse::failure(),
        }
    }
    fn handle_inner(
        &mut self,
        request: DispatcherRequest,
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<()> {
        if request.contract() != 1 {
            return Err(blocked());
        }
        if let Some(identity) = request.identity() {
            self.layout.authorize(identity)?;
        }
        if !request.is_mutation() {
            return Ok(());
        }
        let _guard = MutationGuard::acquire(&self.installation.root)?;
        match request {
            DispatcherRequest::Start { .. } => self.start(primitive),
            DispatcherRequest::Stop { .. } => self.stop(primitive),
            DispatcherRequest::Cleanup { .. } => {
                self.stop(primitive)?;
                self.installation.cleanup_previous()
            }
            _ => Ok(()),
        }
    }
    fn start(
        &mut self,
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.channel_failed {
            return Err(blocked());
        }
        if let Some(child) = self.child.as_mut() {
            return if child.try_wait()?.is_none() {
                Ok(())
            } else {
                Err(blocked())
            };
        }
        if self.installation.root.join(ACTIVE_ENGINE_NAME).exists() {
            return Err(blocked());
        }
        self.spawn(primitive)
    }
    fn spawn(
        &mut self,
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<()> {
        let verified = self.installation.load()?;
        verified.authorize(&self.layout.identity)?;
        let marker = self.installation.root.join(ACTIVE_ENGINE_NAME);
        if !marker.exists() {
            write_new(
                &marker,
                &serde_json::to_vec(&self.layout.identity).map_err(|_| blocked())?,
            )?;
        }
        let mut command = std::process::Command::new(verified.engine_path());
        #[cfg(windows)]
        own_dispatcher_job()?;
        command
            .arg("--engine-mode")
            .arg(&self.installation.root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(unix)]
        {
            command.env(
                "PATH",
                format!(
                    "{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    verified
                        .engine_path()
                        .parent()
                        .ok_or_else(blocked)?
                        .display()
                ),
            );
        }
        #[cfg(unix)]
        let tree_owner = own_process_group(&mut command)?;
        match command.spawn() {
            Ok(child) => {
                self.child = Some(child);
                #[cfg(unix)]
                {
                    self.tree_owner = Some(tree_owner);
                }
                self.channel_failed = false;
            }
            Err(error) => {
                fs::remove_file(marker)?;
                return Err(error);
            }
        }
        let response = self.exchange(
            &encode_frame(&serde_json::json!({"dispatcher_control":"ready"}))?,
            primitive,
        )?;
        let response: serde_json::Value =
            serde_json::from_slice(frame_body(&response, MAX_ENGINE_FRAME)?)
                .map_err(|_| blocked())?;
        if response.get("engine_ready") != Some(&serde_json::Value::Bool(true)) {
            return Err(blocked());
        }
        Ok(())
    }
    fn stop(
        &mut self,
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<()> {
        let marker = self.installation.root.join(ACTIVE_ENGINE_NAME);
        if self.channel_failed {
            #[cfg(unix)]
            {
                self.tree_owner = None;
            }
            if let Some(child) = self.child.as_mut() {
                if child.try_wait()?.is_none() {
                    child.kill()?;
                }
                child.wait()?;
            }
            self.child = None;
        }
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_some() {
                self.child = None;
                #[cfg(unix)]
                {
                    self.tree_owner = None;
                }
            }
        }
        if self.child.is_none() && marker.exists() {
            // A crashed owner may have left tunnel state. Never adopt a live
            // orphan; recover only after its kernel-held lifetime lease ends.
            let lease = MutationGuard::at(&self.installation.root.join("engine-owner.lock"))?;
            drop(lease);
            let identity: EngineIdentity =
                serde_json::from_slice(&read_bounded(&marker, MAX_DISPATCHER_FRAME)?)
                    .map_err(|_| blocked())?;
            self.layout.authorize(&identity)?;
            self.spawn(primitive)?;
        }
        if self.child.is_none() {
            return Ok(());
        }
        let response = self.exchange(
            &encode_frame(&serde_json::json!({"dispatcher_control":"stop"}))?,
            primitive,
        )?;
        let response: serde_json::Value =
            serde_json::from_slice(frame_body(&response, MAX_ENGINE_FRAME)?)
                .map_err(|_| blocked())?;
        if response.get("engine_stopped") != Some(&serde_json::Value::Bool(true)) {
            return Err(blocked());
        }
        let child = self.child.as_mut().ok_or_else(blocked)?;
        drop(child.stdin.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.child = None;
        #[cfg(unix)]
        {
            self.tree_owner = None;
        }
        fs::remove_file(marker)?;
        Ok(())
    }
    pub fn relay(
        &mut self,
        frame: &[u8],
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        frame_body(frame, MAX_ENGINE_FRAME)?;
        let _guard = MutationGuard::acquire(&self.installation.root)?;
        if self.child.is_none() {
            return Err(blocked());
        }
        self.exchange(frame, primitive)
    }
    fn exchange(
        &mut self,
        frame: &[u8],
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let result = self.exchange_inner(frame, primitive);
        if result.is_err() {
            self.channel_failed = true;
        }
        result
    }
    fn exchange_inner(
        &mut self,
        frame: &[u8],
        primitive: &mut impl FnMut(EnginePrimitive) -> io::Result<()>,
    ) -> io::Result<Vec<u8>> {
        let child = self.child.as_mut().ok_or_else(blocked)?;
        let input = child.stdin.as_mut().ok_or_else(blocked)?;
        input.write_all(frame)?;
        input.flush()?;
        for _ in 0..16 {
            let response =
                read_frame(child.stdout.as_mut().ok_or_else(blocked)?, MAX_ENGINE_FRAME)?;
            if let Ok(control) =
                serde_json::from_slice::<PrimitiveRequest>(frame_body(&response, MAX_ENGINE_FRAME)?)
            {
                let result = primitive(control.engine_primitive);
                input.write_all(&encode_frame(
                    &serde_json::json!({"primitive_ok":result.is_ok()}),
                )?)?;
                input.flush()?;
            } else {
                return Ok(response);
            }
        }
        Err(blocked())
    }
}
impl Drop for ProcessDispatcher {
    fn drop(&mut self) {
        // EOF asks the engine to stop. The persistent marker deliberately stays
        // until a future dispatcher obtains explicit stop acknowledgement.
        if let Some(child) = self.child.as_mut() {
            drop(child.stdin.take());
        }
    }
}
