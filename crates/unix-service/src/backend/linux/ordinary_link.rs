use super::{
    amneziawg_command, backend_error, boot_identity, capture_member, inspect_member,
    kernel_interface_group, kernel_interface_index, userspace_socket_path,
    validate_root_owned_binary, verify_member, LinuxIdentity, LinuxOrdinaryRoutes, MemberTransport,
    NativeProof, ResourceMode, ServiceError, SessionScope, TunnelTransport, COMMAND_TIMEOUT,
};
use crate::backend::{
    linux_owner::Intent,
    redundancy::{
        remove_userspace_member, socket_identity, unlink_socket_identity, SocketIdentity,
    },
};
use crate::member_network::journal::ScopedJournal;
use crate::process::status_with_timeout;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, ErrorKind},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

const MODE: ResourceMode = ResourceMode::Single;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OrdinaryLink {
    identity: LinuxIdentity,
    pub(super) ready: bool,
    pub(super) dns_entry: Option<String>,
    // Old AWG journals attest the socket and index. New launches also attest
    // the link group and use it to find a socket staged before fd handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    awg_group: Option<u32>,
}
impl OrdinaryLink {
    pub(super) fn transport(&self) -> TunnelTransport {
        match self.identity.proof {
            NativeProof::Kernel { .. } => TunnelTransport::WireGuard,
            NativeProof::Userspace(_) => TunnelTransport::AmneziaWg3,
        }
    }

    fn present(&self) -> Result<(bool, bool), ServiceError> {
        match self.identity.proof {
            NativeProof::Kernel { .. } => {
                match inspect_member(&self.identity).map_err(backend_error)? {
                    Some(actual) if actual == self.identity => Ok((true, true)),
                    None => Ok((false, false)),
                    Some(_) => Err(unconfirmed()),
                }
            }
            NativeProof::Userspace(expected) => {
                let interface = &self.identity.interface;
                let index = kernel_interface_index(interface)?;
                let socket = socket_at(&userspace_socket_path(interface))?;
                if index != 0
                    && (index != self.identity.index
                        || match self.awg_group {
                            Some(group) => {
                                kernel_interface_group(interface).map_err(backend_error)? != group
                            }
                            None => socket.is_none(),
                        })
                    || socket.is_some_and(|socket| socket != expected)
                    || kernel_interface_index(interface)? != index
                {
                    return Err(unconfirmed());
                }
                Ok((index != 0, socket.is_some()))
            }
        }
    }

    fn staged_socket(&self) -> Result<Option<PathBuf>, ServiceError> {
        let (Some(group), NativeProof::Userspace(expected)) =
            (self.awg_group, &self.identity.proof)
        else {
            return Ok(None);
        };
        let path = stage_path(&self.identity.interface, group)?;
        match socket_at(&path)? {
            Some(actual) if actual == *expected => Ok(Some(path)),
            None => Ok(None),
            Some(_) => Err(unconfirmed()),
        }
    }
}

// Untagged so the existing format-1 captured record and null remain readable.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Phase {
    Starting(Starting),
    Owned(OrdinaryLink),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Starting {
    launch: Intent,
}

pub(super) struct OrdinaryLinkStore {
    file: ScopedJournal<Option<Phase>>,
    phase: Option<Phase>,
}
impl OrdinaryLinkStore {
    pub(super) fn open(root: &Path) -> Result<Self, ServiceError> {
        let private = root.join("ordinary-routing");
        if create_directory(&private, 0o700)? {
            File::open(root)
                .and_then(|f| f.sync_all())
                .map_err(backend_error)?;
        }
        let scope = SessionScope {
            runtime: nelomai_contracts::RuntimeSlot::Latest,
            runtime_generation: 1,
            session_id: "00000000-0000-4000-8000-000000000001".into(),
            connection_generation: 1,
        };
        let file = ScopedJournal::open_named(&private, scope, 0, "ordinary-link.json")
            .map_err(backend_error)?;
        let phase = file.load().map_err(backend_error)?.flatten();
        let mut store = Self { file, phase };
        let boot = boot_identity()?;
        match &store.phase {
            Some(Phase::Starting(Starting { launch })) => {
                if !launch.valid() {
                    return Err(unconfirmed());
                }
                if launch.boot != boot {
                    store.clear()?;
                } else {
                    inspect_starting(launch)?;
                }
            }
            Some(Phase::Owned(record)) => {
                let id = &record.identity;
                if id.interface != MODE.linux_interface(record.transport())
                    || id.index == 0
                    || record.awg_group.is_some_and(|group| {
                        record.transport() != TunnelTransport::AmneziaWg3
                            || !(1..=i32::MAX as u32).contains(&group)
                    })
                    || record
                        .dns_entry
                        .as_ref()
                        .is_some_and(|s| !valid_dns_entry(s, &id.interface))
                {
                    return Err(unconfirmed());
                }
                if id.boot != boot {
                    store.clear()?;
                } else {
                    match record.present()? {
                        (true, true) => (),
                        (false, false)
                            if record.dns_entry.is_none() && record.staged_socket()?.is_none() =>
                        {
                            store.clear()?;
                        }
                        _ => {
                            store.owned_mut().expect("loaded record").ready = false;
                            store.persist()?;
                        }
                    }
                }
            }
            None => (),
        }
        if store.phase.is_none() {
            for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
                if kernel_interface_index(MODE.linux_interface(transport))? != 0 {
                    return Err(unconfirmed());
                }
            }
        }
        Ok(store)
    }

    pub(super) fn owned(&self) -> Option<&OrdinaryLink> {
        match &self.phase {
            Some(Phase::Owned(record)) => Some(record),
            _ => None,
        }
    }

    pub(super) fn owned_mut(&mut self) -> Option<&mut OrdinaryLink> {
        match &mut self.phase {
            Some(Phase::Owned(record)) => Some(record),
            _ => None,
        }
    }

    pub(super) fn cleanup_pending(&self) -> bool {
        match &self.phase {
            Some(Phase::Starting(_)) => true,
            Some(Phase::Owned(record)) => !record.ready,
            None => false,
        }
    }

    pub(super) fn verify(&self, index: u32) -> Result<(), ServiceError> {
        let record = self.owned().ok_or(ServiceError::InvalidRequest)?;
        if record.identity.index != index {
            return Err(unconfirmed());
        }
        self.verify_active()
    }

    pub(super) fn verify_active(&self) -> Result<(), ServiceError> {
        let record = self.owned().ok_or(ServiceError::InvalidRequest)?;
        if record.present()? != (true, true) {
            return Err(unconfirmed());
        }
        Ok(())
    }

    pub(super) fn persist(&mut self) -> Result<(), ServiceError> {
        self.file.save_state(&self.phase).map_err(backend_error)
    }

    fn clear(&mut self) -> Result<(), ServiceError> {
        self.file.save_state(&None).map_err(backend_error)?;
        self.phase = None;
        Ok(())
    }

    fn capture(
        &mut self,
        identity: LinuxIdentity,
        awg_group: Option<u32>,
    ) -> Result<(), ServiceError> {
        self.phase = Some(Phase::Owned(OrdinaryLink {
            identity,
            ready: false,
            dns_entry: None,
            awg_group,
        }));
        self.persist()
    }

    pub(super) fn launch(
        &mut self,
        executable: &Path,
        runtime: &Path,
        transport: MemberTransport,
        boot: &str,
    ) -> Result<(), ServiceError> {
        let launch = Intent::new(transport, boot).map_err(backend_error)?;
        let interface = launch.interface(MODE);
        if self.phase.is_some() || boot_identity()? != boot {
            return Err(unconfirmed());
        }
        require_absent(interface)?;
        let awg_paths = if transport == MemberTransport::AmneziaWg3 {
            validate_root_owned_binary(executable)?;
            let socket = userspace_socket_path(interface);
            let directory = socket.parent().ok_or_else(unconfirmed)?;
            create_directory(directory, 0o755)?;
            require_private_directory(directory, 0o022)?;
            let stage = staging_directory(directory);
            create_directory(&stage, 0o700)?;
            require_private_directory(&stage, 0o077)?;
            let stage = stage_path(interface, launch.group)?;
            if socket_at(&stage)?.is_some() {
                return Err(unconfirmed());
            }
            Some((stage, socket))
        } else {
            None
        };
        self.phase = Some(Phase::Starting(Starting {
            launch: launch.clone(),
        }));
        self.persist()?;

        if let Some((stage, socket)) = awg_paths {
            let tun = create_tun(interface).map_err(backend_error)?;
            let index = kernel_interface_index(interface)?;
            LinuxOrdinaryRoutes::set_link_group(index, launch.group)?;
            let listener = UnixListener::bind(&stage).map_err(backend_error)?;
            fs::set_permissions(&stage, fs::Permissions::from_mode(0o600))
                .map_err(backend_error)?;
            let proof = socket_at(&stage)?.ok_or_else(unconfirmed)?;
            self.capture(
                LinuxIdentity {
                    boot: boot.into(),
                    interface: interface.into(),
                    index,
                    proof: NativeProof::Userspace(proof),
                },
                Some(launch.group),
            )?;
            // Publish exclusively with the same inode. The daemon can retain
            // the TUN only after its link and socket proof are durable.
            publish_socket(&stage, &socket).map_err(backend_error)?;
            self.verify(index)?;
            let mut command = amneziawg_command(executable, interface, runtime);
            inherit_awg_fds(&mut command, &tun, &listener);
            if !status_with_timeout(&mut command, COMMAND_TIMEOUT)
                .map_err(backend_error)?
                .success()
            {
                return Err(backend_error("amneziawg_go_start_failed"));
            }
            Ok(())
        } else {
            // The send runs in this process. An external ip child could
            // create the link after a restarted helper observed its absence.
            LinuxOrdinaryRoutes::create_wireguard_link(interface, launch.group)?;
            let identity = capture_member(interface, transport, boot).map_err(backend_error)?;
            if !launch.matches_kernel(&identity) {
                return Err(unconfirmed());
            }
            self.capture(identity, None)
        }
    }

    pub(super) fn stop(&mut self) -> Result<(), ServiceError> {
        if let Some(Phase::Starting(Starting { launch })) = &self.phase {
            let live = inspect_starting(launch)?;
            if let Some(identity) = live {
                verify_member(&identity).map_err(backend_error)?;
                LinuxOrdinaryRoutes::delete_link(identity.index)?;
                if inspect_member(&identity).map_err(backend_error)?.is_some() {
                    return Err(cleanup_pending());
                }
            } else if launch.transport == MemberTransport::AmneziaWg3 {
                let path = stage_path(launch.interface(MODE), launch.group)?;
                if let Some(socket) = socket_at(&path)? {
                    unlink_socket_identity(&path, 0, socket).map_err(backend_error)?;
                }
            }
            return self.clear();
        }
        let Some(mut record) = self.owned().cloned() else {
            return Ok(());
        };
        record.ready = false;
        self.phase = Some(Phase::Owned(record.clone()));
        let durable = self.persist();
        let live = record.present()?;
        let dns_cleanup = record
            .dns_entry
            .as_ref()
            .map(|entry| {
                let status = status_with_timeout(
                    Command::new("resolvconf").args(["-d", entry, "-f"]),
                    COMMAND_TIMEOUT,
                )
                .map_err(backend_error)?;
                if status.success() {
                    Ok(())
                } else {
                    Err(backend_error("ordinary_dns_cleanup_failed"))
                }
            })
            .transpose();
        match record.identity.proof {
            NativeProof::Kernel { .. } if live.0 => {
                verify_member(&record.identity).map_err(backend_error)?;
                LinuxOrdinaryRoutes::delete_link(record.identity.index)?;
            }
            NativeProof::Userspace(socket) => {
                if let Some(path) = record.staged_socket()? {
                    unlink_socket_identity(&path, 0, socket).map_err(backend_error)?;
                }
                if live != (false, false) {
                    record.present()?;
                    remove_userspace_member(&record.identity.interface, socket)?;
                }
            }
            _ => (),
        }
        if record.present()? != (false, false) || record.staged_socket()?.is_some() {
            return Err(cleanup_pending());
        }
        dns_cleanup?;
        durable?;
        self.clear()
    }
}

fn inspect_starting(launch: &Intent) -> Result<Option<LinuxIdentity>, ServiceError> {
    let interface = launch.interface(MODE);
    if boot_identity()? != launch.boot {
        return Err(unconfirmed());
    }
    if launch.transport == MemberTransport::AmneziaWg3 {
        // The helper's exclusive nonpersistent TUN closes on process exit.
        // The daemon cannot inherit it before the Owned record is durable.
        require_absent(interface)?;
        return Ok(None);
    }
    if kernel_interface_index(interface)? == 0 {
        return Ok(None);
    }
    let identity =
        capture_member(interface, launch.transport, &launch.boot).map_err(backend_error)?;
    if launch.matches_kernel(&identity) {
        Ok(Some(identity))
    } else {
        Err(unconfirmed())
    }
}

fn require_absent(interface: &str) -> Result<(), ServiceError> {
    if kernel_interface_index(interface)? != 0
        || socket_at(&userspace_socket_path(interface))?.is_some()
    {
        return Err(unconfirmed());
    }
    Ok(())
}

fn socket_at(path: &Path) -> Result<Option<SocketIdentity>, ServiceError> {
    match socket_identity(path, 0) {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(backend_error(error)),
    }
}

fn create_directory(path: &Path, mode: u32) -> Result<bool, ServiceError> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(backend_error(error)),
    }
}

fn require_private_directory(path: &Path, writable_by: u32) -> Result<(), ServiceError> {
    let meta = fs::symlink_metadata(path).map_err(backend_error)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & writable_by != 0 {
        return Err(unconfirmed());
    }
    Ok(())
}

fn staging_directory(socket_directory: &Path) -> PathBuf {
    socket_directory.join(".nelomai-ordinary")
}

fn stage_path(interface: &str, group: u32) -> Result<PathBuf, ServiceError> {
    let socket = userspace_socket_path(interface);
    let socket_directory = socket.parent().ok_or_else(unconfirmed)?;
    let stage = staging_directory(socket_directory);
    // The socket and staging directory may both be absent after teardown.
    // Reject any replacement symlink or writable ancestor before inspecting.
    for (directory, mode) in [(socket_directory, 0o022), (stage.as_path(), 0o077)] {
        match fs::symlink_metadata(directory) {
            Ok(_) => require_private_directory(directory, mode)?,
            Err(error) if error.kind() == ErrorKind::NotFound => break,
            Err(error) => return Err(backend_error(error)),
        }
    }
    Ok(stage.join(format!("{group:08x}.sock")))
}

fn create_tun(interface: &str) -> io::Result<File> {
    let tun = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/dev/net/tun")?;
    if interface.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(ErrorKind::InvalidInput, "invalid_tun_name"));
    }
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (to, from) in request.ifr_name.iter_mut().zip(interface.bytes()) {
        *to = from as libc::c_char;
    }
    request.ifr_ifru.ifru_flags =
        (libc::IFF_TUN | libc::IFF_TUN_EXCL | libc::IFF_NO_PI | libc::IFF_VNET_HDR)
            as libc::c_short;
    if unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(tun)
}

fn publish_socket(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn inherit_awg_fds(command: &mut Command, tun: &File, listener: &UnixListener) {
    let tun = tun.as_raw_fd();
    let listener = listener.as_raw_fd();
    command
        .env("WG_TUN_FD", tun.to_string())
        .env("WG_UAPI_FD", listener.to_string())
        .env_remove("WG_PROCESS_FOREGROUND");
    // The files stay open until the child starts. Only the child's descriptor
    // table changes, so unrelated commands cannot inherit these descriptors.
    unsafe {
        command.pre_exec(move || {
            for fd in [tun, listener] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn valid_dns_entry(entry: &str, interface: &str) -> bool {
    entry == interface
        || entry.split_once('.').is_some_and(|(prefix, suffix)| {
            suffix == interface
                && !prefix.is_empty()
                && prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn unconfirmed() -> ServiceError {
    backend_error("ordinary_tunnel_ownership_unconfirmed")
}

fn cleanup_pending() -> ServiceError {
    backend_error("ordinary_tunnel_cleanup_pending")
}

#[cfg(test)]
mod tests;
