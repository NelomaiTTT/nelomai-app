//! Signed-runtime source pin only. This does NOT authorize executable loading,
//! Wintun maintenance, native creation or adoption; factory remains disabled.
#![allow(dead_code)]
use crate::member_carrier::{CarrierError as Error, Result};
use nelomai_contracts::{
    dispatcher::EngineIdentity, RuntimeFileRole, RuntimeFileV1, VerifiedContainerManifest,
};

/// Compiled runtime resources, never an IPC path or DLL-search fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LibraryKind {
    Wintun,
    WireGuard,
    Tunnel,
    AmneziaWgTunnel,
}
impl LibraryKind {
    fn path(self) -> &'static str {
        match self {
            Self::Wintun => "wintun.dll",
            Self::WireGuard => "wireguard.dll",
            Self::Tunnel => "tunnel.dll",
            Self::AmneziaWgTunnel => "amneziawg-tunnel.dll",
        }
    }
}
fn member_libraries(transport: nelomai_client_tunnel::TunnelTransport) -> [LibraryKind; 2] {
    use nelomai_client_tunnel::TunnelTransport;
    match transport {
        TunnelTransport::WireGuard => [LibraryKind::WireGuard, LibraryKind::Tunnel],
        TunnelTransport::AmneziaWg3 => [LibraryKind::Wintun, LibraryKind::AmneziaWgTunnel],
    }
}

fn wintun_entry(
    manifest: &VerifiedContainerManifest,
    manifest_digest: &str,
    identity: &EngineIdentity,
) -> Result<RuntimeFileV1> {
    library_entry(manifest, manifest_digest, identity, LibraryKind::Wintun)
}
fn library_entry(
    manifest: &VerifiedContainerManifest,
    manifest_digest: &str,
    identity: &EngineIdentity,
    kind: LibraryKind,
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
        .find(|entry| entry.path == kind.path())
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
        rc::Rc,
        sync::Arc,
    };

    /// No path/name/manifest/identity supplied by IPC can construct this.
    /// Holds the SAME actual runtime owner lock and non-replaceable source
    /// handles. A borrow is still NOT permission to execute the module.
    struct LibrarySource {
        installation: Installation,
        identity: EngineIdentity,
        directory: PathBuf,
        executable: PathBuf,
        owner: Arc<MutationGuard>,
        root: Box<dyn Fn() -> Result<()>>,
        payload: PinnedPayload,
        kind: LibraryKind,
    }
    impl LibrarySource {
        fn new(root: &Path, owner: Arc<MutationGuard>, kind: LibraryKind) -> Result<Self> {
            owner
                .verify_at(&root.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)?;
            let root_pin = pin_private_directory(root).map_err(|_| Error::Conflict)?;
            #[cfg(test)]
            let installation = super::super::member_carrier_factory_test_os::installation(root)
                .map(Ok)
                .unwrap_or_else(|| Installation::production(root))
                .map_err(|_| Error::Conflict)?;
            #[cfg(not(test))]
            let installation = Installation::production(root).map_err(|_| Error::Conflict)?;
            let executable = actual_executable()?;
            let layout = installation
                .load_engine(&executable)
                .map_err(|_| Error::Conflict)?;
            let entry = read_signed_entry(&layout.directory, &layout.identity, kind)?;
            // Fixed sibling of the authenticated kernel executable, NEVER a
            // caller path or a platform DLL-search fallback.
            let path = layout.engine_path().with_file_name(kind.path());
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
                kind,
            };
            source.verify()?;
            Ok(source)
        }
        fn verify(&self) -> Result<()> {
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
                || layout.engine_path().with_file_name(self.kind.path()) != self.payload.path()
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
        fn verify_owner(&self, owner: &Arc<MutationGuard>) -> Result<()> {
            if !Arc::ptr_eq(&self.owner, owner) {
                return Err(Error::Conflict);
            }
            self.verify()
        }
        fn file(&self) -> Result<&File> {
            self.verify()?;
            Ok(self.payload.file())
        }
        fn path(&self) -> Result<&Path> {
            self.verify()?;
            Ok(self.payload.path())
        }
        fn identity(&self) -> &EngineIdentity {
            &self.identity
        }
    }
    /// Actual original Wintun source; preserves the existing opaque API.
    pub(crate) struct WintunSource(LibrarySource);
    impl WintunSource {
        pub(crate) fn new(root: &Path, owner: Arc<MutationGuard>) -> Result<Self> {
            LibrarySource::new(root, owner, LibraryKind::Wintun).map(Self)
        }
        pub(crate) fn verify(&self) -> Result<()> {
            self.0.verify()
        }
        /// SAME authenticated installed container, distinct from its engine
        /// payload directory. This returns no module or effect authority.
        pub(in crate::windows) fn manifest_directory(&self) -> Result<&Path> {
            self.0.verify()?;
            Ok(&self.0.directory)
        }
        pub(in crate::windows) fn verify_owner(&self, owner: &Arc<MutationGuard>) -> Result<()> {
            self.0.verify_owner(owner)
        }
        /// Repeat-load comparison only. Both independently authenticated held
        /// sources must identify the SAME original file and engine owner. Never
        /// construct a source/module/permission from path, digest or file ID.
        pub(in crate::windows) fn verify_process_anchor_origin(
            &self,
            original: &Self,
        ) -> Result<()> {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            };
            if self.0.directory != original.0.directory
                || self.0.executable != original.0.executable
                || self.0.payload.path() != original.0.payload.path()
            {
                return Err(Error::Conflict);
            }
            let id = |source: &Self| -> Result<(u32, u32, u32)> {
                let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
                if unsafe {
                    GetFileInformationByHandle(source.0.payload.file().as_raw_handle(), &mut info)
                } == 0
                {
                    return Err(Error::Native);
                }
                Ok((
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                ))
            };
            original.verify()?;
            if !std::ptr::eq(self, original) {
                self.verify()?;
            }
            let held = id(original)?;
            let compare = |current| {
                super::super::member_carrier_module::compare_process_source_origin(
                    &original.0.owner,
                    &self.0.owner,
                    &original.0.identity,
                    &self.0.identity,
                    held,
                    current,
                )
                .map_err(|_| Error::Conflict)
            };
            compare(id(self)?)?;
            original.verify()?;
            if !std::ptr::eq(self, original) {
                self.verify()?;
            }
            if id(original)? != held {
                return Err(Error::Conflict);
            }
            compare(id(self)?)?;
            Ok(())
        }
        pub(crate) fn file(&self) -> Result<&File> {
            self.0.file()
        }
        pub(crate) fn path(&self) -> Result<&Path> {
            self.0.path()
        }
        pub(crate) fn identity(&self) -> &EngineIdentity {
            self.0.identity()
        }
    }

    /// Signed member DLLs retained under the SAME real owner as C. This is
    /// readonly source retention, NOT an original service/NIC ACK, permission
    /// to load/execute/install a driver, or authorization of native effects.
    /// AWG keeps the actual original C Wintun source, never a reopened substitute.
    pub(crate) struct MemberSource {
        transport: nelomai_client_tunnel::TunnelTransport,
        carrier: Rc<WintunSource>,
        libraries: Vec<LibrarySource>,
    }
    impl MemberSource {
        pub(crate) fn new(
            root: &Path,
            owner: Arc<MutationGuard>,
            transport: nelomai_client_tunnel::TunnelTransport,
            carrier: &Rc<WintunSource>,
        ) -> Result<Self> {
            carrier.verify_owner(&owner)?;
            let mut libraries = Vec::with_capacity(2);
            for kind in member_libraries(transport) {
                if kind != LibraryKind::Wintun {
                    libraries.push(LibrarySource::new(root, owner.clone(), kind)?);
                }
            }
            let source = Self {
                transport,
                carrier: carrier.clone(),
                libraries,
            };
            source.verify_owner(&owner)?;
            Ok(source)
        }
        pub(in crate::windows) fn verify_owner(&self, owner: &Arc<MutationGuard>) -> Result<()> {
            let wanted = member_libraries(self.transport);
            let expected = wanted
                .into_iter()
                .filter(|kind| *kind != LibraryKind::Wintun)
                .collect::<Vec<_>>();
            if self.libraries.len() != expected.len() {
                return Err(Error::Conflict);
            }
            // One complete signed runtime read covers BOTH slots and ALL of
            // their payloads. Join every original library to that SAME owner,
            // root, executable and manifest before and after that read; do not
            // reload/hash the entire runtime once per individual library pin.
            let pins = || {
                let carrier = &self.carrier.0;
                if !Arc::ptr_eq(&carrier.owner, owner) {
                    return Err(Error::Conflict);
                }
                carrier
                    .owner
                    .verify_at(&carrier.installation.root.join("engine-owner.lock"))
                    .map_err(|_| Error::Conflict)?;
                (carrier.root)()?;
                carrier.payload.verify().map_err(|_| Error::Conflict)?;
                for (library, kind) in self.libraries.iter().zip(&expected) {
                    if library.kind != *kind
                        || !Arc::ptr_eq(&library.owner, owner)
                        || library.identity() != carrier.identity()
                        || library.installation.root != carrier.installation.root
                        || library.directory != carrier.directory
                        || library.executable != carrier.executable
                        || library.payload.path() != carrier.executable.with_file_name(kind.path())
                    {
                        return Err(Error::Conflict);
                    }
                    (library.root)()?;
                    library.payload.verify().map_err(|_| Error::Conflict)?;
                }
                carrier
                    .owner
                    .verify_at(&carrier.installation.root.join("engine-owner.lock"))
                    .map_err(|_| Error::Conflict)
            };
            pins()?;
            self.carrier.verify_owner(owner)?;
            pins()
        }
        pub(crate) fn identity(&self) -> &EngineIdentity {
            self.carrier.identity()
        }
        pub(crate) fn transport(&self) -> nelomai_client_tunnel::TunnelTransport {
            self.transport
        }
        pub(in crate::windows) fn matches_carrier(&self, carrier: &Rc<WintunSource>) -> bool {
            Rc::ptr_eq(&self.carrier, carrier)
        }
        pub(crate) fn verify(&self) -> Result<()> {
            self.verify_owner(&self.carrier.0.owner)
        }
    }
    fn actual_executable() -> Result<PathBuf> {
        #[cfg(test)]
        if let Some(path) = crate::windows::member_carrier_factory_test_os::executable() {
            return std::fs::canonicalize(path).map_err(|_| Error::Native);
        }
        std::fs::canonicalize(std::env::current_exe().map_err(|_| Error::Native)?)
            .map_err(|_| Error::Native)
    }
    fn read_signed_entry(
        directory: &Path,
        identity: &EngineIdentity,
        kind: LibraryKind,
    ) -> Result<RuntimeFileV1> {
        let bytes = d::read_bounded(&directory.join(d::MANIFEST_NAME), 1024 * 1024)
            .map_err(|_| Error::Conflict)?;
        let signature =
            d::read_bounded(&directory.join(d::SIGNATURE_NAME), 64).map_err(|_| Error::Conflict)?;
        #[cfg(test)]
        let key = crate::windows::member_carrier_factory_test_os::key(directory)
            .map(Ok)
            .unwrap_or_else(d::pinned_key)
            .map_err(|_| Error::Conflict)?;
        #[cfg(not(test))]
        let key = d::pinned_key().map_err(|_| Error::Conflict)?;
        let manifest = nelomai_contracts::verify_container_manifest(
            &bytes, &signature, &key, "windows", "x86_64",
        )
        .map_err(|_| Error::Conflict)?;
        library_entry(&manifest, &d::digest(&bytes), identity, kind)
    }
}

#[cfg(test)]
#[path = "member_carrier_payload_tests.rs"]
mod tests;
