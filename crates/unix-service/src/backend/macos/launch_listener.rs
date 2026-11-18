use super::super::redundancy::{socket_identity, unlink_socket_identity, SocketIdentity};
use super::macos_launch::{self, LaunchReceipt, ProcessStamp};
use super::utun::Utun;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, DirBuilder, Permissions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeferredListener {
    boot: String,
    socket: SocketIdentity,
}

pub(super) struct LaunchListener {
    pub socket: UnixListener,
    pub identity: SocketIdentity,
    staged: PathBuf,
    public: PathBuf,
}

pub(super) fn open_available_utun() -> io::Result<Utun> {
    // Keep occupied units reserved while asking the kernel for the next free
    // one. A stale or foreign socket must be preserved and cannot be handed
    // to the engine. None of these temporary interfaces carry routes.
    let example = super::userspace_socket_path("utun0");
    let directory = example.parent().expect("UAPI directory");
    sweep_deferred(directory)?;
    let collisions = match fs::read_dir(directory) {
        Ok(mut entries) => entries.try_fold(0, |count, entry| entry.map(|_| count + 1))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    let mut occupied = Vec::new();
    for _ in 0..=collisions {
        let utun = Utun::open()?;
        match fs::symlink_metadata(super::userspace_socket_path(utun.name())) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(utun),
            Ok(_) => occupied.push(utun),
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "utun_uapi_names_occupied",
    ))
}

impl LaunchListener {
    pub(super) fn bind(receipt: &LaunchReceipt) -> io::Result<Self> {
        let (staged, public) = paths(receipt)?;
        let private = staged.parent().expect("launch socket has a directory");
        directory(public.parent().expect("UAPI directory"), 0o755, true)?;
        directory(private, 0o700, true)?;
        let socket = UnixListener::bind(&staged)?;
        fs::set_permissions(&staged, Permissions::from_mode(0o600))?;
        let identity = socket_identity(&staged, 0)?;
        Ok(Self {
            socket,
            identity,
            staged,
            public,
        })
    }

    /// The caller has durably recorded the inode. Publish the same listener
    /// while preserving an existing path of any type.
    pub(super) fn publish(&self) -> io::Result<()> {
        let from = CString::new(self.staged.as_os_str().as_bytes())?;
        let to = CString::new(self.public.as_os_str().as_bytes())?;
        if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// A listener can survive a killed process as a filesystem entry. Recovery
/// cleans the public name only after the kernel lets us reserve it again.
pub(super) fn retire(receipt: &LaunchReceipt) -> io::Result<()> {
    let (staged, public) = paths(receipt)?;
    if !directory(public.parent().expect("UAPI directory"), 0o755, false)? {
        return Ok(());
    }
    let recorded = receipt.managed.as_ref().and_then(|managed| managed.socket);
    if let Some((managed, expected)) = receipt.managed.as_ref().zip(recorded) {
        retire_public(
            &managed.name,
            managed.index,
            expected,
            ListenerOwner::Starting,
        )?;
    }
    if directory(
        staged.parent().expect("private UAPI directory"),
        0o700,
        false,
    )? {
        if let Some(actual) = observed(&staged)? {
            // Before the inode was saved, this nonce-specific slot was private
            // to the helper. The public path was still untouched.
            if recorded.is_none_or(|expected| expected == actual) {
                unlink_socket_identity(&staged, 0, actual)?;
            }
        }
    }
    Ok(())
}

pub(super) enum ListenerOwner {
    Starting,
    Verified(ProcessStamp),
    Legacy,
}

pub(super) fn retire_public(
    name: &str,
    index: u32,
    expected: SocketIdentity,
    owner: ListenerOwner,
) -> io::Result<()> {
    let path = super::userspace_socket_path(name);
    directory(path.parent().expect("UAPI directory"), 0o755, false)?;
    // A new engine might acquire the just-released unit and publish its own
    // listener. Reserve the name before the final inode check and unlink.
    let deadline = Instant::now() + super::START_TIMEOUT;
    let _reservation = loop {
        match super::utun::reserve_name(name) {
            Ok(reservation) => break reservation,
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                let current = super::kernel_ifindex(name)?;
                if current != 0 && current != index {
                    return defer_public(name, &path, expected);
                }
                if let ListenerOwner::Verified(process) = owner {
                    if !macos_launch::process_alive(process)? {
                        // A foreign VPN can reuse both name and index. Our
                        // old daemon can no longer hold the old descriptor.
                        return defer_public(name, &path, expected);
                    }
                }
                if Instant::now() >= deadline {
                    // Start did not configure a peer or routes before the
                    // Owned record. Once its own listener is gone, a foreign
                    // listener on the same name cannot fence future starts.
                    if matches!(owner, ListenerOwner::Starting)
                        && (observed(&path)? != Some(expected)
                            || macos_launch::probe_listener(&path).is_err_and(|error| {
                                matches!(
                                    error.raw_os_error(),
                                    Some(libc::ENOENT | libc::ECONNREFUSED)
                                )
                            }))
                    {
                        return defer_public(name, &path, expected);
                    }
                    return Err(io::Error::other("userspace_cleanup_pending"));
                }
                // An old interface may be invisible before its unit is reusable.
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    };
    unlink_if_owned(&path, expected)
}

fn defer_public(name: &str, public: &Path, socket: SocketIdentity) -> io::Result<()> {
    if observed(public)? != Some(socket) {
        return Ok(());
    }
    let private = public
        .parent()
        .expect("UAPI directory")
        .join(".nelomai-launch");
    directory(&private, 0o700, true)?;
    let boot = super::boot_identity().map_err(io::Error::other)?;
    super::save_json_state(
        &private.join(format!("retired-{name}.json")),
        &DeferredListener { boot, socket },
    )
    .map_err(io::Error::other)
}

fn sweep_deferred(public: &Path) -> io::Result<()> {
    if !directory(public, 0o755, false)? {
        return Ok(());
    }
    let private = public.join(".nelomai-launch");
    if !directory(&private, 0o700, false)? {
        return Ok(());
    }
    let boot = super::boot_identity().map_err(io::Error::other)?;
    for entry in fs::read_dir(private)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name
            .to_str()
            .and_then(|name| name.strip_prefix("retired-"))
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|name| {
                name.strip_prefix("utun").is_some_and(|unit| {
                    !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
        else {
            continue;
        };
        let path = entry.path();
        super::validate_state_file(&path, "deferred_listener_untrusted")
            .map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        fs::File::open(&path)?.take(1025).read_to_end(&mut bytes)?;
        let saved: DeferredListener = serde_json::from_slice(&bytes)?;
        if saved.boot == boot {
            let _reservation = match super::utun::reserve_name(name) {
                Ok(reservation) => reservation,
                Err(error) if error.raw_os_error() == Some(libc::EBUSY) => continue,
                Err(error) => return Err(error),
            };
            unlink_if_owned(&super::userspace_socket_path(name), saved.socket)?;
        }
        super::remove_regular_file_if_present(&path)?;
    }
    Ok(())
}

pub(super) fn unlink_if_owned(path: &Path, expected: SocketIdentity) -> io::Result<()> {
    if observed(path)? == Some(expected) {
        unlink_socket_identity(path, 0, expected)?;
    }
    Ok(())
}

pub(super) fn observed(path: &Path) -> io::Result<Option<SocketIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == 0 => {
            Ok(Some(SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn paths(receipt: &LaunchReceipt) -> io::Result<(PathBuf, PathBuf)> {
    if !receipt.valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid launch receipt",
        ));
    }
    let managed = receipt
        .managed
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing managed utun"))?;
    let public = super::userspace_socket_path(&managed.name);
    let private = public
        .parent()
        .expect("UAPI directory")
        .join(".nelomai-launch");
    Ok((private.join(&receipt.launch_nonce), public))
}

fn directory(path: &Path, mode: u32, create: bool) -> io::Result<bool> {
    if create {
        match DirBuilder::new().mode(mode).create(path) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(error),
        }
    }
    let forbidden = if mode == 0o700 { 0o077 } else { 0o022 };
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && meta.uid() == 0 && meta.mode() & forbidden == 0 => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "untrusted UAPI directory",
        )),
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}
