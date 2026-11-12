//! One OS-owned lock for the common container, across every runtime/slot.
//! Keep the file permanently: unlinking a locked inode would permit two owners.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

#[cfg(target_os = "macos")]
#[path = "owner_lock_macos.rs"]
pub(crate) mod macos;

pub(crate) const OWNER_LOCK_FILE: &str = "container-owner.lock";

#[derive(Debug)]
pub struct ContainerOwnerLock {
    _file: File,
    root: PathBuf,
    transition_journal_gate: Mutex<()>,
    #[cfg(target_os = "macos")]
    directories: Option<macos::OwnerDirectories>,
    #[cfg(target_os = "macos")]
    vault_gate: Mutex<()>,
}
impl ContainerOwnerLock {
    pub fn try_acquire(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        let file = Self::open_lock(&root.join("common"))?;
        Self::from_file(root, file)
    }

    /// Acquire the same permanent Common lock while pinning its directories
    /// for the macOS vault. Both acquisition paths exclude each other.
    /// The vault root must be an absolute path without symbolic links.
    #[cfg(target_os = "macos")]
    pub fn try_acquire_for_macos_vault(root: &Path) -> io::Result<Self> {
        let directories = macos::OwnerDirectories::open(root)?;
        let file = directories.open_lock()?;
        let mut owner = Self::from_file(root.to_path_buf(), file)?;
        directories.check(owner.root(), owner.locked_file())?;
        owner.directories = Some(directories);
        Ok(owner)
    }

    fn from_file(root: PathBuf, file: File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: live owned file descriptor; flock does not take ownership.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err(io::Error::other("container owner locking is unsupported"));
        Ok(Self {
            _file: file,
            root,
            transition_journal_gate: Mutex::new(()),
            #[cfg(target_os = "macos")]
            directories: None,
            #[cfg(target_os = "macos")]
            vault_gate: Mutex::new(()),
        })
    }

    fn open_lock(common: &Path) -> io::Result<File> {
        match fs::create_dir(common) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(common, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if !fs::symlink_metadata(common)?.file_type().is_dir() {
            return Err(io::Error::other(
                "container common directory is not a directory",
            ));
        }
        let path = common.join(OWNER_LOCK_FILE);
        if fs::symlink_metadata(&path).is_ok_and(|m| !m.file_type().is_file()) {
            return Err(io::Error::other(
                "container owner lock is not a regular file",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // A kernel-enforced exclusive open, not a process-local mutex.
            // No other container can open this permanent file until drop/exit.
            options.share_mode(0);
        }
        options.open(path)
    }
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn locked_file(&self) -> &File {
        &self._file
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn vault_directories(&self) -> io::Result<&macos::OwnerDirectories> {
        self.directories
            .as_ref()
            .ok_or_else(|| io::Error::other("owner lock has no vault directory descriptors"))
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn lock_vault(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.vault_gate
            .lock()
            .map_err(|_| io::Error::other("vault operation lock poisoned"))
    }

    /// Short process-local serialization for the common transition journal.
    /// Callers must release this before network, child, or auth waits.
    pub fn lock_transition_journal(&self) -> io::Result<MutexGuard<'_, ()>> {
        self.transition_journal_gate
            .lock()
            .map_err(|_| io::Error::other("container transition journal lock poisoned"))
    }
}
