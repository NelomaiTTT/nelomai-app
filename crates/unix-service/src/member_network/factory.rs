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
