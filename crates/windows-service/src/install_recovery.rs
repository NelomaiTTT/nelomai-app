//! Installer-only cleanup of a stale lifetime. No process launch or VPN start.
use crate::dispatcher::{self as d, Installation, VerifiedLayout};
use std::io;

pub(crate) fn recover(
    installation: &Installation,
    cleanup_owned: impl FnOnce(&VerifiedLayout) -> io::Result<()>,
) -> io::Result<()> {
    let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
    if !marker.try_exists()? {
        return Ok(());
    }
    // Serialize the entire check/cleanup/retirement against dispatcher startup
    // and installation. Holding the second kernel lock proves the old engine
    // lifetime is gone and prevents adoption of an orphan.
    let _mutation = d::MutationGuard::acquire(&installation.root)?;
    let _lifetime = d::MutationGuard::at(&installation.root.join("engine-owner.lock"))?;
    let owner = d::ProcessDispatcher::new(installation.clone())?;
    let bytes = d::read_bounded(&marker, d::MAX_DISPATCHER_FRAME)?;
    let identity: d::EngineIdentity = serde_json::from_slice(&bytes).map_err(|_| d::blocked())?;
    owner.layout.authorize(&identity)?;
    cleanup_owned(&owner.layout)?;
    // A cleanup ACK alone cannot authorize retiring a different lifetime.
    if d::read_bounded(&marker, d::MAX_DISPATCHER_FRAME)? != bytes {
        return Err(d::blocked());
    }
    std::fs::remove_file(marker)
}

#[cfg(test)]
#[path = "install_recovery_tests.rs"]
mod tests;
