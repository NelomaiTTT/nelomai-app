use crate::{
    owner_lock::macos::{current_uid, open_directory_at, require_private, verify_entry},
    ContainerOwnerLock, StorageError,
};
use rustix::fs::{self, AtFlags, Mode, OFlags, RenameFlags};
use std::{
    fs::{File, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
};

const FILE_FLAGS: OFlags = OFlags::NOFOLLOW
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const STAGED_VAULT: &str = ".vault-pending";
const STAGED_RECORD: &str = ".record-pending";

impl From<rustix::io::Errno> for StorageError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

pub(super) fn check_common(owner: &ContainerOwnerLock) -> Result<(), StorageError> {
    owner
        .vault_directories()?
        .check(owner.root(), owner.locked_file())?;
    Ok(())
}

pub(super) fn open_private_directory(parent: &File, name: &str) -> Result<File, StorageError> {
    let dir = open_directory_at(parent, name)?;
    require_private(&dir, 0o700)?;
    Ok(dir)
}

pub(super) fn check_directory(parent: &File, name: &str, dir: &File) -> Result<(), StorageError> {
    verify_entry(parent, name, dir)?;
    Ok(require_private(dir, 0o700)?)
}

pub(super) fn create_vault(
    owner: &ContainerOwnerLock,
    name: &str,
    binding: (&str, &[u8]),
) -> Result<File, StorageError> {
    let common = &owner.vault_directories()?.common;
    check_common(owner)?;
    remove_staged_vault(common, binding.0)?;
    fs::mkdirat(common, STAGED_VAULT, Mode::RWXU)?;
    // mkdirat applies umask even to owner permissions.
    fs::chmodat(common, STAGED_VAULT, Mode::RWXU, AtFlags::SYMLINK_NOFOLLOW)?;
    let staged = open_private_directory(common, STAGED_VAULT)?;
    write_record(&staged, binding.0, binding.1)?;
    check_common(owner)?;
    check_directory(common, STAGED_VAULT, &staged)?;
    fs::renameat_with(common, STAGED_VAULT, common, name, RenameFlags::NOREPLACE)?;
    Ok(staged)
}

pub(super) fn recover_directory(
    owner: &ContainerOwnerLock,
    directory: &File,
    binding_name: &str,
) -> Result<(), StorageError> {
    // The owner holds the in-process vault gate. Pending data never reached
    // the rename commit, so it can be removed without inspecting ciphertext.
    remove_staged_vault(&owner.vault_directories()?.common, binding_name)?;
    remove_owned_file(directory, STAGED_RECORD)?;
    directory.sync_all()?;
    sync_ancestor(&owner.vault_directories()?.common)?;
    // The owner may have just created root or its ancestors. Synchronize the
    // parent entries up to the root of this filesystem as well.
    let mut dir = owner.vault_directories()?.root.try_clone()?;
    loop {
        sync_ancestor(&dir)?;
        let parent = open_directory_at(&dir, "..")?;
        let here = dir.metadata()?;
        let there = parent.metadata()?;
        if here.dev() != there.dev() || here.ino() == there.ino() {
            break;
        }
        dir = parent;
    }
    Ok(())
}

fn remove_staged_vault(common: &File, binding_name: &str) -> Result<(), StorageError> {
    match fs::unlinkat(common, STAGED_VAULT, AtFlags::REMOVEDIR) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(rustix::io::Errno::NOTEMPTY) => {}
        Err(error) => return Err(error.into()),
    }
    let stage = open_private_directory(common, STAGED_VAULT)?;
    remove_owned_file(&stage, STAGED_RECORD)?;
    remove_owned_file(&stage, binding_name)?;
    verify_entry(common, STAGED_VAULT, &stage)?;
    fs::unlinkat(common, STAGED_VAULT, AtFlags::REMOVEDIR)?;
    Ok(())
}

fn remove_owned_file(directory: &File, name: &str) -> Result<(), StorageError> {
    let meta = match fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(meta) => meta,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // A crash can leave a mode-000 inode before fchmod runs.
    if meta.st_mode & libc::S_IFMT != libc::S_IFREG
        || meta.st_nlink != 1
        || meta.st_uid != current_uid()
    {
        return Err(StorageError::RecoveryRequired("invalid vault staging file"));
    }
    fs::unlinkat(directory, name, AtFlags::empty())?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_ANCESTOR_SYNC: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(super) fn fail_ancestor_sync_after(successes: usize) {
    FAIL_ANCESTOR_SYNC.set(Some(successes));
}

fn sync_ancestor(directory: &File) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_ANCESTOR_SYNC.with(|fail| match fail.get() {
        Some(0) => {
            fail.set(None);
            true
        }
        Some(count) => {
            fail.set(Some(count - 1));
            false
        }
        None => false,
    }) {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    directory.sync_all()
}

pub(super) fn open_record(directory: &File, name: &str) -> Result<Option<File>, StorageError> {
    let file = match fs::openat(directory, name, OFlags::RDONLY | FILE_FLAGS, Mode::empty()) {
        Ok(file) => File::from(file),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    check_record(&file)?;
    Ok(Some(file))
}

pub(super) fn remove_record(directory: &File, name: &str) -> Result<(), StorageError> {
    let Some(file) = open_record(directory, name)? else {
        return Ok(());
    };
    verify_entry(directory, name, &file)?;
    fs::unlinkat(directory, name, AtFlags::empty())?;
    directory.sync_all()?;
    Ok(())
}

pub(super) fn write_record(directory: &File, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
    remove_owned_file(directory, STAGED_RECORD)?;
    let mut file = File::from(fs::openat(
        directory,
        STAGED_RECORD,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | FILE_FLAGS,
        Mode::RUSR | Mode::WUSR,
    )?);
    let result = (|| {
        file.set_permissions(Permissions::from_mode(0o600))?;
        check_record(&file)?;
        file.write_all(bytes)?;
        // On macOS File::sync_all uses F_FULLFSYNC.
        file.sync_all()?;
        #[cfg(test)]
        if std::env::var_os("NELOMAI_VAULT_INTERRUPTED_WRITE_ROOT").is_some() {
            std::process::exit(77);
        }
        verify_entry(directory, STAGED_RECORD, &file)?;
        fs::renameat(directory, STAGED_RECORD, directory, name)?;
        directory.sync_all()?;
        Ok(())
    })();
    if result.is_err() && verify_entry(directory, STAGED_RECORD, &file).is_ok() {
        let _ = fs::unlinkat(directory, STAGED_RECORD, AtFlags::empty());
    }
    result
}

fn check_record(file: &File) -> Result<(), StorageError> {
    let meta = file.metadata()?;
    // A concurrent atomic replacement may unlink this already-open inode.
    if !meta.is_file() || meta.nlink() > 1 {
        return Err(StorageError::RecoveryRequired(
            "vault record is not private",
        ));
    }
    Ok(require_private(file, 0o600)?)
}
