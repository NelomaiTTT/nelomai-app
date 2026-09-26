#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_tunnel::TunnelTransport;
    use nelomai_contracts::dispatcher::TunnelSlot;
    use std::path::Path;

    #[test]
    fn native_members_never_own_common_routes_or_dns() {
        for slot in [TunnelSlot::A, TunnelSlot::B] {
            assert!(!ResourceMode::Member(slot).owns_network());
        }
        assert!(ResourceMode::Single.owns_network());
    }

    #[test]
    fn member_state_and_interfaces_do_not_alias_each_other_or_single() {
        let mut names = std::collections::HashSet::new();
        let mut paths = std::collections::HashSet::new();
        for mode in [
            ResourceMode::Single,
            ResourceMode::Member(TunnelSlot::A),
            ResourceMode::Member(TunnelSlot::B),
        ] {
            assert!(paths.insert(mode.runtime_path(Path::new("/private/session"))));
            for transport in [TunnelTransport::WireGuard, TunnelTransport::AmneziaWg3] {
                let name = mode.linux_interface(transport);
                assert!(name.len() < 16);
                assert!(names.insert(name));
            }
        }
        assert_eq!(
            ResourceMode::Member(TunnelSlot::A).runtime_path(Path::new("/private/session")),
            Path::new("/private/session/slot-a")
        );
    }

    #[test]
    fn removal_is_only_for_the_owned_socket_not_regular_files_or_symlinks() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.sock");
        let b = dir.path().join("b.sock");
        let _a = UnixListener::bind(&a).unwrap();
        let _b = UnixListener::bind(&b).unwrap();
        let owner = unsafe { libc::geteuid() };
        assert!(unlink_owned_socket(&a, owner.wrapping_add(1)).is_err());
        assert!(a.exists() && b.exists());
        unlink_owned_socket(&a, owner).unwrap();
        assert!(!a.exists() && b.exists());
        unlink_owned_socket(&a, owner).unwrap();
        let link = dir.path().join("link");
        symlink(&b, &link).unwrap();
        assert!(unlink_owned_socket(&link, owner).is_err());
        assert!(b.exists());
        let regular = dir.path().join("state");
        std::fs::write(&regular, b"keep").unwrap();
        assert!(unlink_owned_socket(&regular, owner).is_err());
        assert_eq!(std::fs::read(regular).unwrap(), b"keep");
    }

    #[test]
    fn replaced_socket_is_not_removed_by_previous_member() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot.sock");
        let _old = UnixListener::bind(&path).unwrap();
        let owner = unsafe { libc::geteuid() };
        let identity = socket_identity(&path, owner).unwrap();
        // Keep the old inode linked, ensuring it cannot be reused by the fixture.
        std::fs::rename(&path, dir.path().join("old.sock")).unwrap();
        let _new = UnixListener::bind(&path).unwrap();
        assert!(unlink_socket_identity(&path, owner, identity).is_err());
        assert!(path.exists());
        let current = socket_identity(&path, owner).unwrap();
        unlink_socket_identity(&path, owner, current).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn failed_kernel_delete_keeps_identity_for_retry_and_never_deletes_replacement() {
        struct Kernel {
            index: u32,
            failures: usize,
            deletes: usize,
        }
        impl KernelMemberControl for Kernel {
            fn index(&mut self) -> Result<u32, crate::ServiceError> {
                Ok(self.index)
            }
            fn delete(&mut self) -> Result<(), crate::ServiceError> {
                self.deletes += 1;
                if self.failures > 0 {
                    self.failures -= 1;
                    return Err(crate::ServiceError::Backend("injected".into()));
                }
                self.index = 0;
                Ok(())
            }
        }
        let mut identity = Some(20);
        let mut control = Kernel {
            index: 20,
            failures: 1,
            deletes: 0,
        };
        assert!(remove_kernel_member(&mut identity, &mut control).is_err());
        assert_eq!(identity, Some(20));
        control.index = 21;
        assert!(remove_kernel_member(&mut identity, &mut control).is_err());
        assert_eq!(control.deletes, 1);
        control.index = 20;
        remove_kernel_member(&mut identity, &mut control).unwrap();
        assert_eq!(identity, None);
        assert_eq!(control.deletes, 2);
        remove_kernel_member(&mut identity, &mut control).unwrap();
        assert_eq!(control.deletes, 2);
    }
}
#[cfg(any(target_os = "linux", test))]
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::TunnelSlot;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", test))]
pub(super) trait KernelMemberControl {
    fn index(&mut self) -> Result<u32, crate::ServiceError>;
    fn delete(&mut self) -> Result<(), crate::ServiceError>;
}

#[cfg(any(target_os = "linux", test))]
pub(super) fn remove_kernel_member<C: KernelMemberControl>(
    identity: &mut Option<u32>,
    control: &mut C,
) -> Result<(), crate::ServiceError> {
    let current = control.index()?;
    if current == 0 {
        *identity = None;
        return Ok(());
    }
    if *identity != Some(current) {
        return Err(crate::ServiceError::Backend(
            "slot_interface_identity_changed".into(),
        ));
    }
    control.delete()?;
    if control.index() != Ok(0) {
        return Err(crate::ServiceError::Backend(
            "slot_interface_cleanup_pending".into(),
        ));
    }
    *identity = None;
    Ok(())
}

// WG/AWG userspace backends exit when their UAPI socket is removed. The vendor
// remove_interface also mutates DNS (machine-wide on macOS), so members cannot
// use that combined operation. Only the session owner calls this under its lock.
pub(super) fn remove_userspace_member(
    interface: &str,
    identity: SocketIdentity,
) -> Result<(), crate::ServiceError> {
    let path = super::userspace_socket_path(interface);
    unlink_socket_identity(&path, 0, identity)
        .map_err(|_| crate::ServiceError::Backend("slot_socket_cleanup_failed".into()))?;
    let name =
        std::ffi::CString::new(interface).map_err(|_| crate::ServiceError::InvalidRequest)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
        if std::time::Instant::now() >= deadline {
            return Err(crate::ServiceError::Backend(
                "slot_interface_cleanup_pending".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn capture_userspace_member(
    interface: &str,
) -> Result<SocketIdentity, crate::ServiceError> {
    socket_identity(&super::userspace_socket_path(interface), 0)
        .map_err(|_| crate::ServiceError::Backend("slot_socket_ownership_unavailable".into()))
}

fn socket_identity(path: &Path, owner: u32) -> std::io::Result<SocketIdentity> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != owner {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socket ownership mismatch",
        ));
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn unlink_socket_identity(
    path: &Path,
    owner: u32,
    expected: SocketIdentity,
) -> std::io::Result<()> {
    match socket_identity(path, owner) {
        Ok(current) if current == expected => std::fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "socket identity changed",
        )),
    }
}

#[cfg(test)]
fn unlink_owned_socket(path: &Path, owner: u32) -> std::io::Result<()> {
    match socket_identity(path, owner) {
        Ok(identity) => unlink_socket_identity(path, owner, identity),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy)]
pub(super) enum ResourceMode {
    Single,
    Member(TunnelSlot),
}

impl ResourceMode {
    pub(super) fn owns_network(self) -> bool {
        matches!(self, Self::Single)
    }

    pub(super) fn runtime_path(self, root: &Path) -> PathBuf {
        match self {
            Self::Single => root.into(),
            Self::Member(TunnelSlot::A) => root.join("slot-a"),
            Self::Member(TunnelSlot::B) => root.join("slot-b"),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(super) fn linux_interface(self, transport: TunnelTransport) -> &'static str {
        match (self, transport) {
            (Self::Single, TunnelTransport::WireGuard) => "nlm-wg0",
            (Self::Single, TunnelTransport::AmneziaWg3) => "nlm-awg0",
            (Self::Member(TunnelSlot::A), TunnelTransport::WireGuard) => "nlm-wga",
            (Self::Member(TunnelSlot::B), TunnelTransport::WireGuard) => "nlm-wgb",
            (Self::Member(TunnelSlot::A), TunnelTransport::AmneziaWg3) => "nlm-awga",
            (Self::Member(TunnelSlot::B), TunnelTransport::AmneziaWg3) => "nlm-awgb",
        }
    }
}
