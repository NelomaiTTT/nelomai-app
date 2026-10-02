//! Installer-only cleanup of a stale lifetime. No process launch or VPN start.
use crate::dispatcher::{self as d, Installation, VerifiedLayout};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Explicit execution role, not inferred from failed engine authentication or
/// cancellation. Installer authorization is cleanup-only and uses its own full
/// signed incoming package independently of the old installed lifetime.
#[derive(Clone)]
pub(crate) enum RecoveryExecutable {
    Engine,
    Installer { source: PathBuf },
    StagedInstaller,
}
impl RecoveryExecutable {
    pub(crate) fn load(
        &self,
        installation: &Installation,
        executable: &Path,
        slot: nelomai_contracts::RuntimeSlot,
    ) -> io::Result<VerifiedLayout> {
        let layout = match self {
            Self::Engine => installation.load_engine(executable)?,
            Self::Installer { source } => {
                installation.load_installer_recovery(source, executable, slot)?
            }
            Self::StagedInstaller => {
                installation.load_staged_installer_recovery(executable, slot)?
            }
        };
        if layout.identity.slot != slot {
            return Err(d::blocked());
        }
        Ok(layout)
    }
    pub(crate) fn require_engine(&self) -> io::Result<()> {
        match self {
            Self::Engine => Ok(()),
            Self::Installer { .. } | Self::StagedInstaller => Err(d::blocked()),
        }
    }
    /// Role admission only; the caller must authenticate the actual protected
    /// executable, signed layout and SAME owner before each cleanup edge.
    pub(crate) fn require_bounded_cleanup(&self) -> io::Result<()> {
        match self {
            Self::Engine | Self::StagedInstaller => Ok(()),
            Self::Installer { .. } => Err(d::blocked()),
        }
    }
}

/// Read-only SCM configuration comparison. A familiar service name alone is
/// never authority to stop/delete a possibly foreign registration.
pub(crate) fn require_owned_manager_command(
    actual: &[std::ffi::OsString],
    expected: Option<&Path>,
    own_process: bool,
    account: Option<&std::ffi::OsStr>,
) -> io::Result<()> {
    let expected = expected.ok_or_else(d::blocked)?;
    if !own_process
        || account != Some(std::ffi::OsStr::new("LocalSystem"))
        || actual
            != [
                expected.as_os_str().to_owned(),
                std::ffi::OsString::from("--manager-service"),
            ]
    {
        return Err(d::blocked());
    }
    Ok(())
}

/// Supplies the SAME original lifetime lock to the cleanup factory. A new lock
/// acquisition or path-only substitute cannot replace this retained owner.
pub(crate) fn recover_with_owner(
    installation: &Installation,
    cleanup_owned: impl FnOnce(&VerifiedLayout, Arc<d::MutationGuard>) -> io::Result<()>,
) -> io::Result<()> {
    let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
    if !marker.try_exists()? {
        return Ok(());
    }
    // Serialize the entire check/cleanup/retirement against dispatcher startup
    // and installation. Holding the second kernel lock proves the old engine
    // lifetime is gone and prevents adoption of an orphan.
    let mutation = d::MutationGuard::acquire(&installation.root)?;
    let lifetime_path = installation.root.join("engine-owner.lock");
    let lifetime = Arc::new(d::MutationGuard::at(&lifetime_path)?);
    let owner = d::ProcessDispatcher::new(installation.clone())?;
    let bytes = d::read_bounded(&marker, d::MAX_DISPATCHER_FRAME)?;
    let identity: d::EngineIdentity = serde_json::from_slice(&bytes).map_err(|_| d::blocked())?;
    owner.layout.authorize(&identity)?;
    mutation.verify_at(&installation.root.join("mutation.lock"))?;
    lifetime.verify_at(&lifetime_path)?;
    cleanup_owned(&owner.layout, lifetime.clone())?;
    mutation.verify_at(&installation.root.join("mutation.lock"))?;
    lifetime.verify_at(&lifetime_path)?;
    // A cleanup ACK alone cannot authorize retiring a different lifetime.
    if d::read_bounded(&marker, d::MAX_DISPATCHER_FRAME)? != bytes {
        return Err(d::blocked());
    }
    std::fs::remove_file(marker)
}

#[cfg(test)]
pub(crate) fn recover(
    installation: &Installation,
    cleanup_owned: impl FnOnce(&VerifiedLayout) -> io::Result<()>,
) -> io::Result<()> {
    recover_with_owner(installation, |layout, _owner| cleanup_owned(layout))
}

#[cfg(test)]
#[path = "install_recovery_tests.rs"]
mod tests;
