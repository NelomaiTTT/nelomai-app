//! One owner writes; runtimes read bounded tails without issuing auth commands.
use crate::RefreshDiagnosticV1;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Mutex,
};

const ROTATE_AT_BYTES: u64 = 64 * 1024;
static JOURNAL_WRITE: Mutex<()> = Mutex::new(());

pub(crate) fn append(directory: &Path, event: &RefreshDiagnosticV1) -> io::Result<()> {
    append_named(
        directory,
        event,
        "auth-refresh.jsonl",
        "auth-refresh.previous.jsonl",
    )
}

pub(crate) fn append_login(directory: &Path, event: &RefreshDiagnosticV1) -> io::Result<()> {
    append_named(
        directory,
        event,
        "auth-login.jsonl",
        "auth-login.previous.jsonl",
    )
}

#[derive(serde::Serialize)]
pub(crate) struct UpdateFailure<'a> {
    pub timestamp_unix: u64,
    pub kind: &'static str,
    pub stage: &'static str,
    pub code: &'a str,
    pub downloaded_bytes: Option<u64>,
    pub expected_bytes: Option<u64>,
}

pub(crate) fn append_update_failure(directory: &Path, event: &UpdateFailure<'_>) -> io::Result<()> {
    append_named(
        directory,
        event,
        "update-diagnostics.jsonl",
        "update-diagnostics.previous.jsonl",
    )
}

fn append_named(
    directory: &Path,
    event: &impl serde::Serialize,
    current_name: &str,
    previous_name: &str,
) -> io::Result<()> {
    let mut encoded = serde_json::to_vec(event)?;
    encoded.push(b'\n');
    if encoded.len() as u64 > ROTATE_AT_BYTES {
        return Err(io::Error::other("diagnostic record exceeds journal limit"));
    }
    let _write = JOURNAL_WRITE
        .lock()
        .map_err(|_| io::Error::other("diagnostic journal lock unavailable"))?;
    let directory_handle = open_journal_directory(directory)?;
    let mut current = open_journal(&directory_handle, directory, current_name)?;
    let length = current.metadata()?.len();
    if length.saturating_add(encoded.len() as u64) > ROTATE_AT_BYTES {
        let mut previous = open_journal(&directory_handle, directory, previous_name)?;
        // Rotate through the validated handles. Replacing a pathname during
        // rotation cannot redirect either truncation or the append.
        current.seek(SeekFrom::Start(length.saturating_sub(ROTATE_AT_BYTES)))?;
        previous.set_len(0)?;
        io::copy(&mut (&mut current).take(ROTATE_AT_BYTES), &mut previous)?;
        current.set_len(0)?;
    }
    current.seek(SeekFrom::End(0))?;
    current.write_all(&encoded)
}

struct JournalDirectory {
    handle: File,
    #[cfg(windows)]
    _ancestors: Vec<File>,
}

#[cfg(unix)]
fn open_relative(
    parent: &File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::c_int,
) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_journal_directory(directory: &Path) -> io::Result<JournalDirectory> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Component;

    let mut parts = directory.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(io::Error::other("unsafe diagnostic directory"));
    }
    #[cfg(target_os = "macos")]
    let search = libc::O_SEARCH;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let search = libc::O_PATH | libc::O_DIRECTORY;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android")))]
    let search = libc::O_RDONLY | libc::O_DIRECTORY;
    let mut handle = OpenOptions::new()
        .read(true)
        .custom_flags(search | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(io::Error::other("unsafe diagnostic directory"));
        };
        let name = CString::new(name.as_bytes())?;
        handle = match open_relative(&handle, &name, search, 0) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if unsafe { libc::mkdirat(handle.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_relative(&handle, &name, search, 0)?
            }
            Err(error) => return Err(error),
        };
    }
    let handle = open_relative(&handle, c".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    if handle.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::other("unsafe diagnostic directory owner"));
    }
    handle.set_permissions(fs::Permissions::from_mode(0o700))?;
    Ok(JournalDirectory { handle })
}

#[cfg(windows)]
fn open_journal_directory(directory: &Path) -> io::Result<JournalDirectory> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err(io::Error::other("unsafe diagnostic directory"));
    }
    let mut ancestors = Vec::new();
    let mut options = OpenOptions::new();
    // Hold the directory chain without delete sharing until both leaf writes finish.
    options
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let chain: Vec<_> = directory
        .ancestors()
        .filter(|path| path.has_root())
        .collect();
    for path in chain.into_iter().rev() {
        let handle = match options.open(path) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound && path.file_name().is_some() => {
                if let Err(error) = fs::create_dir(path) {
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                options.open(path)?
            }
            Err(error) => return Err(error),
        };
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::other("unsafe diagnostic directory"));
        }
        ancestors.push(handle);
    }
    let handle = ancestors
        .pop()
        .ok_or_else(|| io::Error::other("unsafe diagnostic directory"))?;
    Ok(JournalDirectory {
        handle,
        _ancestors: ancestors,
    })
}

#[cfg(not(any(unix, windows)))]
fn open_journal_directory(_directory: &Path) -> io::Result<JournalDirectory> {
    Err(io::ErrorKind::Unsupported.into())
}

fn open_journal(
    directory: &JournalDirectory,
    directory_path: &Path,
    name: &str,
) -> io::Result<File> {
    #[cfg(unix)]
    let file = {
        use std::ffi::CString;
        let _ = directory_path;
        let name = CString::new(name)?;
        open_relative(
            &directory.handle,
            &name,
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?
    };
    #[cfg(not(unix))]
    let file = {
        let _ = &directory.handle;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };
            options
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        options.open(directory_path.join(name))?
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("unsafe diagnostic log"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
            return Err(io::Error::other("unsafe diagnostic log"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || info.nNumberOfLinks != 1
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(io::Error::other("unsafe diagnostic log"));
        }
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn update_failure() -> UpdateFailure<'static> {
        UpdateFailure {
            timestamp_unix: 123,
            kind: "update.operation.failed",
            stage: "download",
            code: "update_download_interrupted",
            downloaded_bytes: Some(512),
            expected_bytes: Some(1024),
        }
    }

    #[cfg(unix)]
    #[test]
    fn update_journal_does_not_append_to_redirected_files_or_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = root_path.join("common");
        fs::create_dir(&directory).unwrap();
        let outside = root_path.join("outside");
        fs::write(&outside, b"unrelated").unwrap();
        let current = directory.join("update-diagnostics.jsonl");
        for hardlink in [false, true] {
            if hardlink {
                fs::hard_link(&outside, &current).unwrap();
            } else {
                std::os::unix::fs::symlink(&outside, &current).unwrap();
            }
            assert!(append_update_failure(&directory, &update_failure()).is_err());
            assert_eq!(fs::read(&outside).unwrap(), b"unrelated");
            fs::remove_file(&current).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn update_journal_does_not_follow_a_redirected_directory() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let outside = root_path.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
        let directory = root_path.join("common");
        symlink(&outside, &directory).unwrap();
        assert!(append_update_failure(&directory, &update_failure()).is_err());
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn update_journal_does_not_follow_redirected_ancestors() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let outside = root_path.join("outside");
        let outside_common = outside.join("common");
        fs::create_dir_all(&outside_common).unwrap();
        fs::set_permissions(&outside_common, fs::Permissions::from_mode(0o755)).unwrap();
        let outside_journal = outside_common.join("update-diagnostics.jsonl");
        fs::write(&outside_journal, b"unrelated").unwrap();
        let link = root_path.join("relocated");
        symlink(&outside, &link).unwrap();
        assert!(append_update_failure(&link.join("common"), &update_failure()).is_err());
        assert_eq!(
            fs::metadata(&outside_common).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read(&outside_journal).unwrap(), b"unrelated");
    }

    #[cfg(unix)]
    #[test]
    fn journal_can_use_a_traverse_only_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().canonicalize().unwrap().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o311)).unwrap();
        let directory = parent.join("common");
        let result = append_update_failure(&directory, &update_failure());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        result.unwrap();
        let log = fs::read_to_string(directory.join("update-diagnostics.jsonl")).unwrap();
        assert!(log.contains("update_download_interrupted"));
    }

    #[cfg(unix)]
    #[test]
    fn update_journal_leaves_current_intact_if_previous_is_redirected() {
        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let directory = root_path.join("common");
        fs::create_dir(&directory).unwrap();
        let outside = root_path.join("outside");
        fs::write(&outside, b"unrelated").unwrap();
        let previous = directory.join("update-diagnostics.previous.jsonl");
        std::os::unix::fs::symlink(&outside, &previous).unwrap();
        let current = directory.join("update-diagnostics.jsonl");
        let original = vec![b'a'; ROTATE_AT_BYTES as usize];
        fs::write(&current, &original).unwrap();
        assert!(append_update_failure(&directory, &update_failure()).is_err());
        assert_eq!(fs::read(&current).unwrap(), original);
        assert!(fs::symlink_metadata(previous).unwrap().is_symlink());
        assert_eq!(fs::read(&outside).unwrap(), b"unrelated");
    }

    #[test]
    fn rotates_bounded_private_journal_and_keeps_original_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().canonicalize().unwrap();
        let event = RefreshDiagnosticV1 {
            timestamp_unix: 123,
            kind: "auth.refresh.complete".into(),
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            code: "saved".into(),
        };
        for _ in 0..2000 {
            append(&directory, &event).unwrap();
        }
        for name in ["auth-refresh.jsonl", "auth-refresh.previous.jsonl"] {
            let path = directory.join(name);
            assert!(path.metadata().unwrap().len() <= ROTATE_AT_BYTES);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            }
            for line in fs::read_to_string(path).unwrap().lines() {
                let saved: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(saved["timestamp_unix"], 123);
                assert_eq!(saved["kind"], "auth.refresh.complete");
                assert_eq!(saved.as_object().unwrap().len(), 4);
            }
        }
    }
}
