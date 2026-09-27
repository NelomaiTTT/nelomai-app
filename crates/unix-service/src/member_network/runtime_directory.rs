//! The engine-lock owner selects this directory; IPC never supplies a path.
use nelomai_client_tunnel::redundancy::SessionScope;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub struct RuntimeDirectory {
    root: PathBuf,
    owner: u32,
}
impl RuntimeDirectory {
    pub fn open(root: &Path) -> io::Result<Self> {
        Self::for_owner(root, 0)
    }
    pub(crate) fn for_owner(root: &Path, owner: u32) -> io::Result<Self> {
        let result = Self {
            root: root.into(),
            owner,
        };
        result.directory(root)?;
        Ok(result)
    }
    /// Preserve completed diagnostic journals under this protected state root.
    /// Never recursively remove an old tree or lose the only cleanup authority.
    pub fn recover(
        &self,
        cleanup: impl FnOnce(&Path, &SessionScope) -> io::Result<()>,
    ) -> io::Result<()> {
        self.directory(&self.root)?;
        let active = self.root.join("active");
        if !exists(&active)? {
            return Ok(());
        }
        let original = self.directory(&active)?;
        if fs::read_dir(&active)?.next().is_none() {
            fs::remove_dir(&active)?;
            fs::File::open(&self.root)?.sync_all()?;
            return Ok(());
        }
        let scope = self.scope(&active)?;
        let completed = self.completed()?;
        let destination = completed.join(scope_key(&scope)?);
        if exists(&destination)? {
            return Err(invalid());
        }
        cleanup(&active, &scope)?;
        if self.directory(&active)? != original || self.scope(&active)? != scope {
            return Err(invalid());
        }
        fs::rename(&active, &destination)?;
        fs::File::open(&completed)?.sync_all()?;
        fs::File::open(&self.root)?.sync_all()
    }
    pub fn create(&self, scope: &SessionScope) -> io::Result<PathBuf> {
        self.directory(&self.root)?;
        if !scope.validate() {
            return Err(invalid());
        }
        let completed = self.completed()?;
        if exists(&completed.join(scope_key(scope)?))? {
            return Err(invalid());
        }
        let active = self.root.join("active");
        fs::DirBuilder::new().mode(0o700).create(&active)?;
        self.directory(&active)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(active)
    }
    fn completed(&self) -> io::Result<PathBuf> {
        let path = self.root.join("completed");
        if !exists(&path)? {
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            fs::File::open(&self.root)?.sync_all()?;
        }
        self.directory(&path)?;
        Ok(path)
    }
    fn directory(&self, path: &Path) -> io::Result<(u64, u64)> {
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != self.owner
            || meta.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        Ok((meta.dev(), meta.ino()))
    }
    fn scope(&self, path: &Path) -> io::Result<SessionScope> {
        self.directory(path)?;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path.join("redundant-session.json"))?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != self.owner
            || meta.mode() & 0o077 != 0
            || meta.len() > 8192
            || meta.nlink() != 1
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err(invalid());
        }
        let envelope: BootEnvelope = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if envelope.format != 1 || !envelope.scope.validate() {
            return Err(invalid());
        }
        Ok(envelope.scope)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootEnvelope {
    format: u16,
    scope: SessionScope,
    #[serde(rename = "state")]
    _state: serde_json::Value,
}
fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn scope_key(scope: &SessionScope) -> io::Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(scope).map_err(|_| invalid())?)
    ))
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "untrusted_pair_runtime_directory",
    )
}

#[cfg(test)]
mod tests {
    use super::super::journal::ScopedJournal;
    use super::*;
    use nelomai_contracts::RuntimeSlot;
    use std::os::unix::fs::PermissionsExt;
    fn scope() -> SessionScope {
        SessionScope {
            runtime: RuntimeSlot::Latest,
            runtime_generation: 10,
            session_id: "11111111-1111-4111-8111-111111111111".into(),
            connection_generation: 3,
        }
    }
    fn fixture() -> (tempfile::TempDir, RuntimeDirectory) {
        let dir = tempfile::Builder::new()
            .prefix("runtime-directory-")
            .tempdir()
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = RuntimeDirectory::for_owner(dir.path(), unsafe { libc::geteuid() }).unwrap();
        (dir, runtime)
    }
    fn seal(path: &Path) {
        let mut journal = ScopedJournal::<serde_json::Value>::open_named(
            path,
            scope(),
            unsafe { libc::geteuid() },
            "redundant-session.json",
        )
        .unwrap();
        journal
            .save_state(&serde_json::json!({"identity":"test-boot"}))
            .unwrap();
    }
    #[test]
    fn old_native_cleanup_finishes_before_new_scope_can_start() {
        let (dir, runtime) = fixture();
        let path = runtime.create(&scope()).unwrap();
        seal(&path);
        let mut next = scope();
        next.connection_generation += 1;
        assert!(runtime.create(&next).is_err());
        assert!(runtime
            .recover(|root, s| {
                assert_eq!(root, path);
                assert_eq!(s, &scope());
                Err(io::Error::other("native still alive"))
            })
            .is_err());
        assert!(path.exists());
        runtime
            .recover(|root, s| {
                assert_eq!(root, path);
                assert_eq!(s, &scope());
                Ok(())
            })
            .unwrap();
        assert!(!path.exists());
        assert!(dir.path().join("completed").exists());
        assert!(runtime.create(&scope()).is_err()); // a stale same-scope Start is never resurrected
        assert_eq!(runtime.create(&next).unwrap(), path);
    }
    #[test]
    fn fresh_recovery_does_not_call_native_and_empty_crash_gap_is_recoverable() {
        let (_dir, runtime) = fixture();
        runtime.recover(|_, _| panic!("no session")).unwrap();
        let path = runtime.create(&scope()).unwrap();
        runtime
            .recover(|_, _| panic!("empty bootstrap has no native owner"))
            .unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn unsealed_contents_and_symlink_never_authorize_native_cleanup_or_deletion() {
        let (dir, runtime) = fixture();
        let path = runtime.create(&scope()).unwrap();
        std::fs::write(path.join("user-file"), b"keep").unwrap();
        assert!(runtime.recover(|_, _| panic!("unsealed")).is_err());
        assert_eq!(std::fs::read(path.join("user-file")).unwrap(), b"keep");
        std::fs::rename(&path, dir.path().join("preserved")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("preserved"), &path).unwrap();
        assert!(runtime.recover(|_, _| panic!("symlink")).is_err());
    }
    #[test]
    fn insecure_or_corrupt_root_never_reaches_native() {
        let (dir, runtime) = fixture();
        let path = runtime.create(&scope()).unwrap();
        seal(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(runtime.recover(|_, _| panic!("insecure")).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(path.join("redundant-session.json"), b"broken").unwrap();
        assert!(runtime.recover(|_, _| panic!("corrupt")).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(runtime.create(&scope()).is_err());
    }
}
