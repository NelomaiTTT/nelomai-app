use super::OWNER_LOCK_FILE;
use rustix::fs::{self, AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
    ptr::NonNull,
};

// The paths only need search permission. A read-only open would fail
// on an ancestor that permits traversal without directory enumeration.
const DIRECTORY_FLAGS: OFlags = OFlags::from_bits_retain(libc::O_SEARCH as _)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const STAGING_PREFIX: &str = ".nelomai-vault-init-";
const LOCK_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

#[derive(Debug)]
pub(crate) struct OwnerDirectories {
    pub(crate) root: File,
    pub(crate) common: File,
}

impl OwnerDirectories {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let root = open_data_root(path, true)?;
        let common = ensure_directory(&root, OsStr::new("common"))?;
        require_private(&common, 0o700)?;
        Ok(Self { root, common })
    }

    pub(super) fn open_lock(&self) -> io::Result<File> {
        let stage = staging_name("lock", OsStr::new(OWNER_LOCK_FILE));
        let file = match self.open_existing_lock() {
            Ok(file) => {
                remove_stage(&self.common, &stage, libc::S_IFREG)?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.create_lock(&stage)?,
            Err(error) => return Err(error),
        };
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 {
            return Err(io::Error::other(
                "container owner lock is not a regular single-link file",
            ));
        }
        Ok(file)
    }

    fn open_existing_lock(&self) -> io::Result<File> {
        Ok(File::from(fs::openat(
            &self.common,
            OWNER_LOCK_FILE,
            LOCK_FLAGS,
            Mode::empty(),
        )?))
    }

    fn create_lock(&self, stage: &str) -> io::Result<File> {
        let common = &self.common;
        let publication = (|| {
            match fs::openat(
                common,
                stage,
                LOCK_FLAGS | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(_) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            #[cfg(test)]
            if std::env::var_os("NELOMAI_VAULT_INTERRUPT_OWNER_FILE_ROOT").is_some() {
                std::process::exit(79);
            }
            prepare_stage(common, stage, libc::S_IFREG, Mode::RUSR | Mode::WUSR)?;
            let file = File::from(fs::openat(common, stage, LOCK_FLAGS, Mode::empty())?);
            publish_stage(common, stage, OsStr::new(OWNER_LOCK_FILE), &file)?;
            Ok(file)
        })();
        match publication {
            Err(ref error) if publication_raced(error) => {
                let file = self.open_existing_lock()?;
                remove_stage(common, stage, libc::S_IFREG)?;
                Ok(file)
            }
            result => result,
        }
    }

    pub(crate) fn check(&self, path: &Path, lock: &File) -> io::Result<()> {
        let actual = open_data_root(path, false)?.metadata()?;
        let pinned = self.root.metadata()?;
        if (actual.dev(), actual.ino()) != (pinned.dev(), pinned.ino()) {
            return Err(location_changed());
        }
        verify_entry(&self.root, "common", &self.common)?;
        require_private(&self.common, 0o700)?;
        verify_entry(&self.common, OWNER_LOCK_FILE, lock)
    }
}

fn ensure_directory(parent: &File, name: &OsStr) -> io::Result<File> {
    let stage = staging_name("dir", name);
    match open_directory_at(parent, name) {
        Ok(directory) => {
            remove_stage(parent, &stage, libc::S_IFDIR)?;
            return Ok(directory);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let publication = (|| {
        match fs::mkdirat(parent, stage.as_str(), Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(test)]
        if name == "common" && std::env::var_os("NELOMAI_VAULT_INTERRUPT_COMMON_ROOT").is_some() {
            std::process::exit(78);
        }
        prepare_stage(parent, &stage, libc::S_IFDIR, Mode::RWXU)?;
        let directory = File::from(fs::openat(
            parent,
            stage.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        #[cfg(test)]
        AFTER_STAGE_OPEN.with(|hook| {
            let action = hook.borrow_mut().take();
            if let Some(action) = action {
                action();
            }
        });
        for entry in fs::Dir::read_from(&directory)? {
            if !matches!(entry?.file_name().to_bytes(), b"." | b"..") {
                // A peer may have published this exact inode and started
                // using it before we read the staged descriptor.
                if verify_entry(parent, name, &directory).is_ok() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                return Err(io::Error::other("owner staging directory is not empty"));
            }
        }
        publish_stage(parent, &stage, name, &directory)?;
        Ok(directory)
    })();
    match publication {
        Err(ref error) if publication_raced(error) => {
            let directory = open_directory_at(parent, name)?;
            remove_stage(parent, &stage, libc::S_IFDIR)?;
            Ok(directory)
        }
        result => result,
    }
}

#[cfg(test)]
type StageOpenHook = Box<dyn FnOnce()>;

#[cfg(test)]
thread_local! {
    static AFTER_STAGE_OPEN: std::cell::RefCell<Option<StageOpenHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn after_stage_open_for_test(action: impl FnOnce() + 'static) {
    AFTER_STAGE_OPEN.with(|hook| hook.replace(Some(Box::new(action))));
}

// Stages are empty and have stable names so either of two concurrent
// acquisitions can finish an interrupted creation. NOREPLACE publishes
// exactly one entry; the losing process opens that same entry.
fn staging_name(kind: &str, name: &OsStr) -> String {
    format!(
        "{STAGING_PREFIX}{kind}-{}-{:x}",
        current_uid(),
        Sha256::digest(name.as_bytes())
    )
}

fn prepare_stage(parent: &File, name: &str, kind: libc::mode_t, mode: Mode) -> io::Result<()> {
    check_stage(parent, name, kind)?;
    fs::chmodat(parent, name, mode, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(())
}

fn check_stage(parent: &File, name: &str, kind: libc::mode_t) -> io::Result<()> {
    let meta = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
    if meta.st_mode & libc::S_IFMT != kind
        || meta.st_uid != current_uid()
        || meta.st_mode & 0o077 != 0
        || (kind == libc::S_IFREG && (meta.st_nlink != 1 || meta.st_size != 0))
    {
        return Err(io::Error::other("invalid owner staging entry"));
    }
    Ok(())
}

fn remove_stage(parent: &File, stage: &str, kind: libc::mode_t) -> io::Result<()> {
    let remove: io::Result<()> = (|| {
        check_stage(parent, stage, kind)?;
        let flags = if kind == libc::S_IFDIR {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        fs::unlinkat(parent, stage, flags)?;
        Ok(())
    })();
    match remove {
        Err(ref error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn publish_stage(parent: &File, stage: &str, name: &OsStr, file: &File) -> io::Result<()> {
    file.sync_all()?;
    if let Err(error) = verify_entry(parent, stage, file) {
        // A different contender can already have published this inode,
        // even if a subsequent attempt has reused the staging name.
        if verify_entry(parent, name, file).is_ok() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        return Err(error);
    }
    fs::renameat_with(parent, stage, parent, name, RenameFlags::NOREPLACE)?;
    Ok(())
}

fn publication_raced(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AlreadyExists | io::ErrorKind::NotFound
    )
}

fn open_data_root(path: &Path, create: bool) -> io::Result<File> {
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(location_changed());
    }
    let mut directory = File::from(fs::open("/", DIRECTORY_FLAGS, Mode::empty())?);
    require_trusted_ancestor(&directory)?;
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(location_changed());
        };
        if name
            .as_bytes()
            .get(..STAGING_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(STAGING_PREFIX.as_bytes()))
        {
            return Err(location_changed());
        }
        directory = if create {
            ensure_directory(&directory, name)?
        } else {
            open_directory_at(&directory, name)?
        };
        require_trusted_ancestor(&directory)?;
    }
    let meta = directory.metadata()?;
    if meta.uid() != current_uid() || meta.mode() & 0o022 != 0 {
        return Err(io::Error::other(
            "vault data root must be writable only by its owner",
        ));
    }
    Ok(directory)
}

fn require_trusted_ancestor(dir: &File) -> io::Result<()> {
    require_ownership_enforcement(dir)?;
    let meta = dir.metadata()?;
    // A sticky directory (such as /private/tmp) permits creation, but
    // protects children owned by the current user or root from other users.
    let mode = meta.mode();
    if (meta.uid() != 0 && meta.uid() != current_uid())
        || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        || ExtendedAcl::read(dir)?.is_some_and(|acl| acl.permits_mutation())
    {
        return Err(io::Error::other(
            "vault ancestor can be modified by another user",
        ));
    }
    Ok(())
}

pub(crate) fn require_private(file: &File, mode: u32) -> io::Result<()> {
    require_ownership_enforcement(file)?;
    let meta = file.metadata()?;
    if meta.uid() != current_uid()
        || meta.mode() & 0o7777 != mode
        || ExtendedAcl::read(file)?.is_some()
    {
        return Err(io::Error::other("vault entry is not private"));
    }
    Ok(())
}

fn require_ownership_enforcement(file: &File) -> io::Result<()> {
    if fs::fstatfs(file)?.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0 {
        return Err(io::Error::other(
            "vault requires a filesystem that enforces ownership",
        ));
    }
    Ok(())
}

pub(crate) fn current_uid() -> libc::uid_t {
    // SAFETY: geteuid takes no arguments and does not mutate process state.
    unsafe { libc::geteuid() }
}

// Darwin sys/acl.h. The ACL owns its entries and releases them together.
type AclHandle = *mut libc::c_void;
const ACL_TYPE_EXTENDED: libc::c_uint = 0x100;
const ACL_FIRST_ENTRY: libc::c_int = 0;
const ACL_NEXT_ENTRY: libc::c_int = -1;
const ACL_EXTENDED_ALLOW: libc::c_uint = 1;
const ACL_EXTENDED_DENY: libc::c_uint = 2;
const ACL_MUTATION: u64 = (1 << 2) // add file
    | (1 << 4) // delete
    | (1 << 5) // add subdirectory
    | (1 << 6) // delete child
    | (1 << 8) // write attributes
    | (1 << 10) // write extended attributes
    | (1 << 12) // write security
    | (1 << 13); // change owner

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_uint) -> AclHandle;
    fn acl_get_entry(acl: AclHandle, entry_id: libc::c_int, entry: *mut AclHandle) -> libc::c_int;
    fn acl_get_tag_type(entry: AclHandle, tag: *mut libc::c_uint) -> libc::c_int;
    fn acl_get_permset_mask_np(entry: AclHandle, mask: *mut u64) -> libc::c_int;
    fn acl_free(acl: AclHandle) -> libc::c_int;
}

struct ExtendedAcl(NonNull<libc::c_void>);

impl ExtendedAcl {
    fn read(file: &File) -> io::Result<Option<Self>> {
        // SAFETY: File owns the live descriptor; the ACL is a Darwin allocation.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if let Some(acl) = NonNull::new(acl) {
            return Ok(Some(Self(acl)));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn permits_mutation(&self) -> bool {
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = std::ptr::null_mut();
            // SAFETY: the valid ACL owns the returned entry until drop.
            if unsafe { acl_get_entry(self.0.as_ptr(), entry_id, &mut entry) } != 0 {
                // Darwin reports EINVAL when the valid ACL has no next entry.
                return io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL);
            }
            let mut tag = 0;
            let mut mask = 0;
            // SAFETY: entry belongs to this ACL; out-parameters have the ABI types.
            if entry.is_null()
                || unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                || (tag != ACL_EXTENDED_DENY
                    && (tag != ACL_EXTENDED_ALLOW
                        || unsafe { acl_get_permset_mask_np(entry, &mut mask) } != 0
                        || mask & ACL_MUTATION != 0))
            {
                return true;
            }
            entry_id = ACL_NEXT_ENTRY;
        }
    }
}

impl Drop for ExtendedAcl {
    fn drop(&mut self) {
        // SAFETY: this allocation was returned by acl_get_fd_np and is owned here.
        unsafe { acl_free(self.0.as_ptr()) };
    }
}

pub(crate) fn open_directory_at(parent: &File, name: impl rustix::path::Arg) -> io::Result<File> {
    Ok(File::from(fs::openat(
        parent,
        name,
        DIRECTORY_FLAGS,
        Mode::empty(),
    )?))
}

pub(crate) fn verify_entry(parent: &File, name: impl AsRef<OsStr>, file: &File) -> io::Result<()> {
    let entry = fs::statat(parent, name.as_ref(), AtFlags::SYMLINK_NOFOLLOW)?;
    let pinned = fs::fstat(file)?;
    if (entry.st_dev, entry.st_ino) != (pinned.st_dev, pinned.st_ino) {
        return Err(location_changed());
    }
    Ok(())
}

fn location_changed() -> io::Error {
    io::Error::other("container storage location changed")
}
