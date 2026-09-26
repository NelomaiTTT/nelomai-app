use nelomai_client_tunnel::redundancy::{
    network::{NetworkJournal, NetworkJournalStore},
    SessionScope,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 8 * 1024 * 1024;
const STATE_FILE: &str = "redundant-network.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: u16,
    scope: SessionScope,
    state: NetworkJournal,
}

pub struct FileNetworkJournal {
    root: PathBuf,
    scope: SessionScope,
    owner: u32,
}

impl FileNetworkJournal {
    pub fn open_root(root: &Path, scope: SessionScope) -> io::Result<Self> {
        Self::open_for_owner(root, scope, 0)
    }
    fn open_for_owner(root: &Path, scope: SessionScope, owner: u32) -> io::Result<Self> {
        if !scope.validate() {
            return Err(untrusted());
        }
        let store = Self {
            root: root.to_path_buf(),
            scope,
            owner,
        };
        store.validate_root()?;
        Ok(store)
    }
    fn validate_root(&self) -> io::Result<()> {
        let meta = fs::symlink_metadata(&self.root)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != self.owner
            || meta.mode() & 0o077 != 0
        {
            return Err(untrusted());
        }
        Ok(())
    }
    pub fn load(&self) -> io::Result<Option<NetworkJournal>> {
        self.validate_root()?;
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join(STATE_FILE))
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.mode() & 0o077 != 0
            || meta.len() > MAX_BYTES
        {
            return Err(untrusted());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(untrusted());
        }
        let saved: Envelope = serde_json::from_slice(&bytes).map_err(|_| untrusted())?;
        if saved.format != 1 || saved.scope != self.scope || !saved.scope.validate() {
            return Err(untrusted());
        }
        Ok(Some(saved.state))
    }
}

impl NetworkJournalStore for FileNetworkJournal {
    fn save(&mut self, state: &NetworkJournal) -> io::Result<()> {
        self.load()?; // Validate existing identity/mode; never overwrite another runtime's journal.
        let bytes = serde_json::to_vec(&Envelope {
            format: 1,
            scope: self.scope.clone(),
            state: state.clone(),
        })
        .map_err(|_| untrusted())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(untrusted());
        }
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let (path, mut file) = (0..32)
            .find_map(|_| {
                let seq = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = self
                    .root
                    .join(format!(".{STATE_FILE}.{}.{seq}.tmp", std::process::id()));
                match OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)
                {
                    Ok(file) => Some(Ok((path, file))),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => None,
                    Err(e) => Some(Err(e)),
                }
            })
            .ok_or_else(|| io::Error::other("journal_temp_collision"))??;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&path, self.root.join(STATE_FILE))?;
            File::open(&self.root)?.sync_all()
        })();
        // This exact create_new file is ours, never an existing stale/user file.
        if result.is_err() {
            let _ = fs::remove_file(&path);
        }
        result
    }
}
fn untrusted() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted_redundant_network_journal",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::RuntimeSlot;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 7,
            session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
            connection_generation: 2,
        }
    }
    fn directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn saved_state_is_private_and_other_runtime_or_start_cannot_adopt_it() {
        let dir = directory();
        let owner = unsafe { libc::geteuid() };
        let mut store = FileNetworkJournal::open_for_owner(dir.path(), scope(), owner).unwrap();
        assert!(store.load().unwrap().is_none());
        store.save(&NetworkJournal::default()).unwrap();
        assert!(store.load().unwrap().is_some());
        assert_eq!(
            fs::metadata(dir.path().join(STATE_FILE)).unwrap().mode() & 0o777,
            0o600
        );
        let mut other = scope();
        other.connection_generation += 1;
        assert!(FileNetworkJournal::open_for_owner(dir.path(), other, owner)
            .unwrap()
            .load()
            .is_err());
        let mut other = scope();
        other.runtime = RuntimeSlot::Stable;
        assert!(FileNetworkJournal::open_for_owner(dir.path(), other, owner)
            .unwrap()
            .load()
            .is_err());
    }
    #[test]
    fn symlinked_journal_is_not_read_or_overwritten() {
        let dir = directory();
        let outside = dir.path().join("keep");
        fs::write(&outside, b"untouched").unwrap();
        symlink(&outside, dir.path().join(STATE_FILE)).unwrap();
        let mut store =
            FileNetworkJournal::open_for_owner(dir.path(), scope(), unsafe { libc::geteuid() })
                .unwrap();
        assert!(store.load().is_err());
        assert!(store.save(&NetworkJournal::default()).is_err());
        assert_eq!(fs::read(outside).unwrap(), b"untouched");
    }
    #[test]
    fn directory_permissions_and_malformed_scope_are_rejected() {
        let dir = directory();
        let owner = unsafe { libc::geteuid() };
        let mut bad = scope();
        bad.session_id = "../../other".into();
        assert!(FileNetworkJournal::open_for_owner(dir.path(), bad, owner).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(FileNetworkJournal::open_for_owner(dir.path(), scope(), owner).is_err());
    }
}
