//! Installed trust inputs. Selection recovery is separate and may only run
//! after this signed container manifest has been verified.
use nelomai_contracts::{verify_container_manifest, VerifiedContainerManifest};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

pub(crate) fn blocked() -> io::Error {
    io::Error::other("runtime_startup_blocked: verified installed manifest, selection and pinned Ed25519 trust are required")
}
pub(crate) fn read_bounded(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| blocked())?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| blocked())?;
    if bytes.len() > max {
        return Err(blocked());
    }
    Ok(bytes)
}
pub(crate) fn verify_installed_manifest(
    resources: &Path,
    pinned_raw_key: Option<&[u8]>,
    platform: &str,
    architecture: &str,
) -> io::Result<VerifiedContainerManifest> {
    let key = pinned_raw_key
        .filter(|key| key.len() == 32)
        .ok_or_else(blocked)?;
    let bytes = read_bounded(&resources.join("container-manifest-v1.json"), 1024 * 1024)?;
    let signature = read_bounded(&resources.join("container-manifest-v1.sig"), 64)?;
    verify_container_manifest(&bytes, &signature, key, platform, architecture)
        .map_err(|_| blocked())
}
