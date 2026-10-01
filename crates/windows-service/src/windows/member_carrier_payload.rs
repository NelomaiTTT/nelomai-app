//! Signed-runtime source pin only. This does NOT authorize executable loading,
//! Wintun maintenance, native creation or adoption; factory remains disabled.
#![allow(dead_code)]
use crate::member_carrier::{CarrierError as Error, Result};
use nelomai_contracts::{
    dispatcher::EngineIdentity, RuntimeFileRole, RuntimeFileV1, VerifiedContainerManifest,
};

fn wintun_entry(
    manifest: &VerifiedContainerManifest,
    manifest_digest: &str,
    identity: &EngineIdentity,
) -> Result<RuntimeFileV1> {
    let selected = manifest.selected(identity.slot).ok_or(Error::Conflict)?;
    if identity.manifest_sha256 != manifest_digest
        || identity.container_version != manifest.manifest().container_version
        || identity.runtime_version != selected.runtime_version
        || identity.runtime_contract_version != selected.contract_version
    {
        return Err(Error::Conflict);
    }
    let entry = selected
        .files
        .iter()
        .find(|entry| entry.path == "wintun.dll")
        .ok_or(Error::Invalid)?;
    if entry.role != RuntimeFileRole::SharedLibrary
        || entry.size_bytes == 0
        || entry.size_bytes > 16 * 1024 * 1024
    {
        return Err(Error::Invalid);
    }
    Ok(entry.clone())
}

#[cfg(windows)]
pub(crate) mod native {
    use super::*;
    use crate::windows::member_files::{pin_private_directory, pin_runtime_payload, PinnedPayload};
    use nelomai_contracts::dispatcher::{self as d, Installation, MutationGuard};
    use std::{
        fs::File,
        path::{Path, PathBuf},
        sync::Arc,
    };

    /// No path/name/manifest/identity supplied by IPC can construct this.
    /// Holds the SAME actual runtime owner lock and non-replaceable source
    /// handles. A borrow is still NOT permission to execute the module.
    pub(crate) struct WintunSource {
        installation: Installation,
        identity: EngineIdentity,
        directory: PathBuf,
        executable: PathBuf,
        owner: Arc<MutationGuard>,
        root: Box<dyn Fn() -> Result<()>>,
        payload: PinnedPayload,
    }
    impl WintunSource {
        pub(crate) fn new(root: &Path, owner: Arc<MutationGuard>) -> Result<Self> {
            owner
                .verify_at(&root.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)?;
            let root_pin = pin_private_directory(root).map_err(|_| Error::Conflict)?;
            let installation = Installation::production(root).map_err(|_| Error::Conflict)?;
            let executable = actual_executable()?;
            let layout = installation
                .load_engine(&executable)
                .map_err(|_| Error::Conflict)?;
            let entry = read_signed_entry(&layout.directory, &layout.identity)?;
            // Fixed sibling of the authenticated kernel executable, NEVER a
            // caller path or a platform DLL-search fallback.
            let path = layout.engine_path().with_file_name("wintun.dll");
            let payload = pin_runtime_payload(&path, entry.size_bytes, &entry.sha256)
                .map_err(|_| Error::Conflict)?;
            let source = Self {
                installation,
                identity: layout.identity,
                directory: layout.directory,
                executable,
                owner,
                root: Box::new(move || root_pin.verify().map_err(|_| Error::Conflict)),
                payload,
            };
            source.verify()?;
            Ok(source)
        }
        pub(crate) fn verify(&self) -> Result<()> {
            self.owner
                .verify_at(&self.installation.root.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)?;
            (self.root)()?;
            self.payload.verify().map_err(|_| Error::Conflict)?;
            if actual_executable()? != self.executable {
                return Err(Error::Conflict);
            }
            let layout = self
                .installation
                .load_engine(&self.executable)
                .map_err(|_| Error::Conflict)?;
            if layout.identity != self.identity
                || layout.directory != self.directory
                || layout.engine_path().with_file_name("wintun.dll") != self.payload.path()
            {
                return Err(Error::Conflict);
            }
            // load_engine independently verifies BOTH signed slots' payloads.
            // The exact original DLL remains write/delete-denied through that
            // verification and all data-only/resource/module borrows.
            self.payload.verify().map_err(|_| Error::Conflict)?;
            (self.root)()?;
            self.owner
                .verify_at(&self.installation.root.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)
        }
        /// The module actor must retain the SAME original privileged lease,
        /// not another correctly named lock or a deserialized runtime identity.
        pub(in crate::windows) fn verify_owner(&self, owner: &Arc<MutationGuard>) -> Result<()> {
            if !Arc::ptr_eq(&self.owner, owner) {
                return Err(Error::Conflict);
            }
            self.verify()
        }
        pub(crate) fn file(&self) -> Result<&File> {
            self.verify()?;
            Ok(self.payload.file())
        }
        pub(crate) fn path(&self) -> Result<&Path> {
            self.verify()?;
            Ok(self.payload.path())
        }
        pub(crate) fn identity(&self) -> &EngineIdentity {
            &self.identity
        }
    }
    fn actual_executable() -> Result<PathBuf> {
        std::fs::canonicalize(std::env::current_exe().map_err(|_| Error::Native)?)
            .map_err(|_| Error::Native)
    }
    fn read_signed_entry(directory: &Path, identity: &EngineIdentity) -> Result<RuntimeFileV1> {
        let bytes = d::read_bounded(&directory.join(d::MANIFEST_NAME), 1024 * 1024)
            .map_err(|_| Error::Conflict)?;
        let signature =
            d::read_bounded(&directory.join(d::SIGNATURE_NAME), 64).map_err(|_| Error::Conflict)?;
        let key = d::pinned_key().map_err(|_| Error::Conflict)?;
        let manifest = nelomai_contracts::verify_container_manifest(
            &bytes, &signature, &key, "windows", "x86_64",
        )
        .map_err(|_| Error::Conflict)?;
        wintun_entry(&manifest, &d::digest(&bytes), identity)
    }
}

#[cfg(test)]
#[path = "member_carrier_payload_tests.rs"]
mod tests;
