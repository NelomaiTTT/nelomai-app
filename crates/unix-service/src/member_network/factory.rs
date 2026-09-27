//! Assemble an owned pair under the existing engine's exclusive runtime lock.
//! The root is selected by the privileged engine, never supplied through IPC.
use super::journal::{FileNetworkJournal, ScopedJournal};
use nelomai_client_tunnel::redundancy::{network::NetworkJournal, SessionScope};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Boot {
    identity: String,
}

pub(crate) struct SessionDirectory {
    pub recovering: bool,
    pub network: FileNetworkJournal,
    pub journal: NetworkJournal,
}
impl SessionDirectory {
    pub(crate) fn open(root: &Path, scope: SessionScope, boot: &str, uid: u32) -> io::Result<Self> {
        if boot.is_empty() || boot.len() > 128 || boot.chars().any(char::is_control) {
            return Err(invalid());
        }
        let mut identity =
            ScopedJournal::<Boot>::open_named(root, scope.clone(), uid, "redundant-session.json")?;
        let saved = identity.load()?;
        let recovering = saved.is_some();
        if let Some(saved) = saved {
            // No route/DNS replay against a different OS boot, where indexes
            // and even identical-looking network resources may be unrelated.
            if saved.identity != boot {
                return Err(invalid());
            }
        } else {
            if fs::read_dir(root)?.next().is_some() {
                return Err(invalid());
            }
            identity.save_state(&Boot {
                identity: boot.into(),
            })?;
        }
        for slot in ["slot-a", "slot-b"] {
            let path = root.join(slot);
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => fs::File::open(root)?.sync_all()?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
            let meta = fs::symlink_metadata(&path)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != uid
                || meta.mode() & 0o077 != 0
            {
                return Err(invalid());
            }
        }
        let mut network = ScopedJournal::<NetworkJournal>::open_named(
            root,
            scope,
            uid,
            "redundant-network.json",
        )?;
        let loaded = network.load()?;
        if recovering && loaded.is_none() {
            for slot in ["slot-a", "slot-b"] {
                if fs::read_dir(root.join(slot))?.next().is_some() {
                    return Err(invalid());
                }
            }
        }
        let journal = loaded.unwrap_or_default();
        if !recovering {
            network.save_state(&journal)?;
        }
        Ok(Self {
            recovering,
            network,
            journal,
        })
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "untrusted_member_session")
}

/// A trusted fresh kernel boot identity invalidates old native indices, not
/// persistent DNS settings. Never construct old members or replay old routes.
/// Keep all files until the enclosing RuntimeDirectory archives this scope.
pub(crate) fn cleanup_previous_boot<
    N: nelomai_client_tunnel::redundancy::network::NetworkSystem,
>(
    root: &Path,
    scope: SessionScope,
    boot: &str,
    uid: u32,
    system: N,
) -> io::Result<bool> {
    let valid = |s: &str| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control);
    if !valid(boot) {
        return Err(invalid());
    }
    let identity =
        ScopedJournal::<Boot>::open_named(root, scope.clone(), uid, "redundant-session.json")?;
    let saved = identity.load()?.ok_or_else(invalid)?;
    if !valid(&saved.identity) {
        return Err(invalid());
    }
    if saved.identity == boot {
        return Ok(false);
    }
    let store =
        ScopedJournal::<NetworkJournal>::open_named(root, scope, uid, "redundant-network.json")?;
    let saved = match store.load()? {
        Some(saved) => saved.persistent_dns_cleanup()?,
        None => {
            // The boot seal is the first write. A crash before the initial
            // network journal is safe only if no member/effect record exists.
            // Unknown files, even in a different boot, are not absence proof.
            require_empty_bootstrap(root, uid)?;
            NetworkJournal::default().persistent_dns_cleanup()?
        }
    };
    let mut owner =
        nelomai_client_tunnel::redundancy::network::NetworkOwner::recover(system, store, saved)?;
    owner.cleanup()?;
    Ok(true)
}

fn require_empty_bootstrap(root: &Path, uid: u32) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        if name == "redundant-session.json" {
            continue; // already read and authenticated by ScopedJournal
        }
        if name != "slot-a" && name != "slot-b" {
            return Err(invalid());
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
            || fs::read_dir(entry.path())?.next().is_some()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub type MacPair = super::session::SessionNetwork<
    crate::backend::PlatformBackend,
    super::macos::MacNetwork<super::macos::NativeMacCommands>,
    FileNetworkJournal,
>;

/// Creates no tunnel and mutates no network state. A reopened directory always
/// yields cleanup-only recovery; callers must finish it before another Start.
/// `root` must already exist, be private/root-owned, and belong to this scope.
#[cfg(target_os = "macos")]
pub fn open_mac_pair(
    root: &Path,
    scope: SessionScope,
    wireguard_go: &Path,
    amneziawg_go: &Path,
) -> Result<MacPair, crate::ServiceError> {
    use crate::backend::PlatformBackend;
    use nelomai_contracts::dispatcher::TunnelSlot;
    let saved = SessionDirectory::open(
        root,
        scope.clone(),
        &crate::backend::macos_boot_identity()?,
        0,
    )
    .map_err(|_| crate::ServiceError::Backend("member_session_recovery_failed".into()))?;
    let backends = [
        PlatformBackend::new_member(
            wireguard_go,
            amneziawg_go,
            root,
            TunnelSlot::A,
            scope.clone(),
        )?,
        PlatformBackend::new_member(
            wireguard_go,
            amneziawg_go,
            root,
            TunnelSlot::B,
            scope.clone(),
        )?,
    ];
    let system = super::macos::MacNetwork {
        commands: super::macos::NativeMacCommands,
    };
    if saved.recovering {
        MacPair::recover_for_cleanup(scope, backends, system, saved.network, saved.journal)
    } else {
        MacPair::new(scope, backends, system, saved.network)
    }
}

#[cfg(target_os = "linux")]
pub type LinuxPair = super::session::SessionNetwork<
    crate::backend::PlatformBackend,
    super::linux::LinuxNetwork<super::linux::NativeLinuxCommands>,
    FileNetworkJournal,
>;

#[cfg(target_os = "linux")]
pub fn open_linux_pair(
    root: &Path,
    scope: SessionScope,
    amneziawg_go: &Path,
) -> Result<LinuxPair, crate::ServiceError> {
    use crate::backend::PlatformBackend;
    let boot = crate::backend::linux_boot_identity()?;
    open_linux_pair_with(
        root,
        scope.clone(),
        &boot,
        0,
        |slot| PlatformBackend::new_member(amneziawg_go, root, slot, scope.clone()),
        super::linux::NativeLinuxCommands::new,
    )
}

/// The root/UID and factories are supplied by the privileged owner, never IPC.
/// Construction may leave bootstrap journals; reopening always fences Start.
#[cfg(any(target_os = "linux", test))]
fn open_linux_pair_with<B: crate::ServiceTunnelBackend, C: super::linux::LinuxNetworkCommands>(
    root: &Path,
    scope: SessionScope,
    boot: &str,
    uid: u32,
    mut backend: impl FnMut(nelomai_contracts::dispatcher::TunnelSlot) -> Result<B, crate::ServiceError>,
    commands: impl FnOnce() -> io::Result<C>,
) -> Result<
    super::session::SessionNetwork<B, super::linux::LinuxNetwork<C>, FileNetworkJournal>,
    crate::ServiceError,
> {
    use super::linux::{bindings::BindingAllocator, LinuxNetwork};
    use nelomai_contracts::dispatcher::TunnelSlot;
    let error =
        |_: io::Error| crate::ServiceError::Backend("member_session_recovery_failed".into());
    let saved = SessionDirectory::open(root, scope.clone(), boot, uid).map_err(error)?;
    // A sealed boot marker is not authority to adopt arbitrary root contents.
    // Each journal's owner validates its UID/mode/scope; the shared coordinator
    // owns redundant-state.json, which this factory must leave untouched.
    for entry in fs::read_dir(root).map_err(error)? {
        let entry = entry.map_err(error)?;
        if !matches!(
            entry.file_name().to_str(),
            Some(
                "redundant-session.json"
                    | "redundant-state.json"
                    | "redundant-network.json"
                    | "redundant-linux-bindings.json"
                    | "slot-a"
                    | "slot-b"
            )
        ) {
            return Err(error(invalid()));
        }
    }
    let allocator =
        BindingAllocator::open_for_owner(root, scope.clone(), boot, uid, !saved.recovering)
            .map_err(error)?;
    // A partial bootstrap can lack a network journal only before any member
    // bindings existed. Pending bindings make the lost route journal ambiguous.
    if saved.network.load().map_err(error)?.is_none() && !allocator.bindings().is_empty() {
        return Err(error(invalid()));
    }
    let backends = [backend(TunnelSlot::A)?, backend(TunnelSlot::B)?];
    let network =
        LinuxNetwork::with_allocator(commands().map_err(error)?, allocator).map_err(error)?;
    if saved.recovering {
        super::session::SessionNetwork::recover_for_cleanup(
            scope,
            backends,
            network,
            saved.network,
            saved.journal,
        )
    } else {
        super::session::SessionNetwork::new(scope, backends, network, saved.network)
    }
}

#[cfg(test)]
#[path = "linux/factory_tests.rs"]
mod linux_tests;
