//! One OS-owned lock for the common container, across every runtime/slot.
//! Keep the file permanently: unlinking a locked inode would permit two owners.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct ContainerOwnerLock {
    _file: File,
    root: PathBuf,
}
impl ContainerOwnerLock {
    pub fn try_acquire(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        let common = root.join("common");
        match fs::create_dir(&common) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&common, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        if !fs::symlink_metadata(&common)?.file_type().is_dir() {
            return Err(io::Error::other(
                "container common directory is not a directory",
            ));
        }
        let path = common.join("container-owner.lock");
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
        let file = options.open(path)?;
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
        Ok(Self { _file: file, root })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
}
