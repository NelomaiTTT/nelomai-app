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
    #[cfg(test)]
    use crate::windows::member_carrier_factory_test_os::trace_step;
    use crate::windows::member_files::{
        pin_installed_files, pin_private_directory, pin_runtime_payload, PinnedDirectory,
        PinnedInstalledFiles, PinnedPayload,
    };
    use nelomai_contracts::dispatcher::{self as d, Installation, MutationGuard, VerifiedLayout};
    use std::{
        fs::File,
        path::{Path, PathBuf},
        rc::Rc,
        sync::Arc,
    };

    /// Trace attribution only; neither variant changes authentication or pins.
    #[derive(Clone, Copy)]
    pub(in crate::windows) enum InstalledRuntimeOrigin {
        Runtime,
        Source,
    }

    /// Complete installed byte proof coupled to SAME original deny-write/delete
    /// handles. Only construction authenticates signatures/hashes; every later
    /// use rechecks actual originals, paths/security, owner and private root.
    /// This grants no module mapping, mutable-context or effect authority.
    pub(in crate::windows) struct PinnedInstalledRuntime {
        layout: VerifiedLayout,
        executable: PathBuf,
        owner: Arc<MutationGuard>,
        root_path: PathBuf,
        root: PinnedDirectory,
        files: PinnedInstalledFiles,
    }
    impl PinnedInstalledRuntime {
        pub(in crate::windows) fn new(
            installation: &Installation,
            executable: &Path,
            owner: Arc<MutationGuard>,
            origin: InstalledRuntimeOrigin,
        ) -> Result<Self> {
            owner
                .verify_at(&installation.root.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)?;
            let layout = Self::authenticate(installation, executable, origin)?;
            Self::acquire_after_authentication(installation, executable, owner, layout, origin)
        }
        fn authenticate(
            installation: &Installation,
            executable: &Path,
            _origin: InstalledRuntimeOrigin,
        ) -> Result<VerifiedLayout> {
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(match _origin {
                InstalledRuntimeOrigin::Runtime => "runtime begin installed payload authentication",
                InstalledRuntimeOrigin::Source => "source begin installed payload authentication",
            });
            let layout = installation
                .load_engine(executable)
                .map_err(|_| Error::Conflict)?;
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(match _origin {
                InstalledRuntimeOrigin::Runtime => "runtime end installed payload authentication",
                InstalledRuntimeOrigin::Source => "source end installed payload authentication",
            });
            Ok(layout)
        }
        fn acquire_after_authentication(
            installation: &Installation,
            executable: &Path,
            owner: Arc<MutationGuard>,
            layout: VerifiedLayout,
            origin: InstalledRuntimeOrigin,
        ) -> Result<Self> {
            let root = pin_private_directory(&installation.root).map_err(|_error| {
                #[cfg(test)]
                trace_step(&format!("installed acquire root pin: {_error:?}"));
                Error::Conflict
            })?;
            let pointer = d::read_bounded(&installation.root.join(d::POINTER_NAME), 96).map_err(
                |_error| {
                    #[cfg(test)]
                    trace_step(&format!("installed acquire pointer read: {_error:?}"));
                    Error::Conflict
                },
            )?;
            let generation = std::str::from_utf8(&pointer).map_err(|_error| {
                #[cfg(test)]
                trace_step(&format!("installed acquire pointer decode: {_error:?}"));
                Error::Conflict
            })?;
            if installation.root.join("releases").join(generation) != layout.directory {
                #[cfg(test)]
                trace_step("installed acquire pointer identity mismatch: Conflict");
                return Err(Error::Conflict);
            }
            let (manifest, manifest_size) =
                read_signed_manifest(&layout.directory, &layout.identity).inspect_err(
                    |_error| {
                        #[cfg(test)]
                        trace_step(&format!("installed acquire signed manifest: {_error:?}"));
                    },
                )?;
            let policy_size =
                d::read_bounded(&layout.directory.join("installation-policy.json"), 8192)
                    .map_err(|_error| {
                        #[cfg(test)]
                        trace_step(&format!("installed acquire policy read: {_error:?}"));
                        Error::Conflict
                    })?
                    .len() as u64;
            let mut inventory = vec![
                (
                    installation.root.join(d::POINTER_NAME),
                    Some(pointer.len() as u64),
                ),
                (layout.directory.join(d::MANIFEST_NAME), Some(manifest_size)),
                (layout.directory.join(d::SIGNATURE_NAME), Some(64)),
                (
                    layout.directory.join("installation-policy.json"),
                    Some(policy_size),
                ),
            ];
            // Include equal-version packaging slots as well as selectable ones.
            for slot in &manifest.manifest().slots {
                let name = match slot.slot {
                    nelomai_contracts::RuntimeSlot::Latest => "latest",
                    nelomai_contracts::RuntimeSlot::Stable => "stable",
                };
                let directory = layout
                    .directory
                    .join("engines")
                    .join(name)
                    .join(&slot.manifest.runtime_version);
                for entry in &slot.manifest.files {
                    inventory.push((directory.join(&entry.path), Some(entry.size_bytes)));
                }
            }
            inventory.push((
                // dispatcher_path() uses a literal "dispatcher/1". Preserve
                // the original lexical ancestors with native component joins;
                // member_files intentionally rejects mixed-separator spelling.
                layout.directory.join("dispatcher").join("1").join(
                    layout
                        .engine_path()
                        .file_name()
                        .expect("verified engine filename"),
                ),
                Some(layout.dispatcher_payload_identity().0),
            ));
            // BrokerPolicy authenticates a digest, not a length. Capture the
            // original handle's length; final full broker hashing below binds
            // it without imposing the DLL's unrelated 16 MiB ceiling.
            inventory.push((layout.broker.executable.clone(), None));
            #[cfg(test)]
            trace_step(&format!(
                "installed acquire inventory count={}",
                inventory.len()
            ));
            let files = pin_installed_files(&inventory).map_err(|_error| {
                #[cfg(test)]
                trace_step(&format!("installed acquire inventory: {_error:?}"));
                Error::Conflict
            })?;
            let current = Self::authenticate(installation, executable, origin)?;
            if current.identity != layout.identity
                || current.directory != layout.directory
                || current.engine_path() != layout.engine_path()
                || current.dispatcher_path() != layout.dispatcher_path()
                || current.dispatcher_payload_identity() != layout.dispatcher_payload_identity()
                || current.broker != layout.broker
                || std::fs::canonicalize(current.engine_path()).map_err(|_| Error::Native)?
                    != executable
            {
                return Err(Error::Conflict);
            }
            let pinned = Self {
                layout,
                executable: executable.to_path_buf(),
                owner,
                root_path: installation.root.clone(),
                root,
                files,
            };
            pinned.verify()?;
            Ok(pinned)
        }
        pub(in crate::windows) fn layout(&self) -> &VerifiedLayout {
            &self.layout
        }
        pub(in crate::windows) fn verify(&self) -> Result<()> {
            #[cfg(test)]
            super::super::member_carrier_factory_test_os::trace_step(
                "installation original pin recheck",
            );
            self.owner
                .verify_at(&self.root_path.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)?;
            self.root.verify().map_err(|_| Error::Conflict)?;
            self.files.verify().map_err(|_| Error::Conflict)?;
            if std::fs::canonicalize(self.layout.engine_path()).map_err(|_| Error::Native)?
                != self.executable
            {
                return Err(Error::Conflict);
            }
            self.root.verify().map_err(|_| Error::Conflict)?;
            self.owner
                .verify_at(&self.root_path.join("engine-owner.lock"))
                .map_err(|_| Error::Conflict)
        }
    }

    /// No path/name/manifest/identity supplied by IPC can construct this.
    /// Holds the SAME actual runtime owner lock and non-replaceable source
    /// handles. A borrow is still NOT permission to execute the module.
    struct LibrarySource {
        installation: Installation,
        installed: PinnedInstalledRuntime,
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
            let installed = PinnedInstalledRuntime::new(
                &installation,
                &executable,
                owner.clone(),
                InstalledRuntimeOrigin::Source,
            )?;
            let layout = installed.layout();
            let entry = read_signed_entry(&layout.directory, &layout.identity, kind)?;
            // Fixed sibling of the authenticated kernel executable, NEVER a
            // caller path or a platform DLL-search fallback.
            let path = layout.engine_path().with_file_name(kind.path());
            let payload = pin_runtime_payload(&path, entry.size_bytes, &entry.sha256)
                .map_err(|_| Error::Conflict)?;
            let source = Self {
                installation,
                identity: layout.identity.clone(),
                directory: layout.directory.clone(),
                installed,
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
            self.payload
                .verify_original()
                .map_err(|_| Error::Conflict)?;
            if actual_executable()? != self.executable {
                return Err(Error::Conflict);
            }
            self.installed.verify()?;
            let layout = self.installed.layout();
            if layout.identity != self.identity
                || layout.directory != self.directory
                || std::fs::canonicalize(layout.engine_path()).map_err(|_| Error::Native)?
                    != self.executable
                || layout.engine_path().with_file_name(self.kind.path()) != self.payload.path()
            {
                return Err(Error::Conflict);
            }
            // BOTH signed slots' complete byte proof stays coupled to retained
            // original OS handles. The strict exact DLL pin is also checked on
            // both sides of every data-only/resource/module borrow.
            self.payload
                .verify_original()
                .map_err(|_| Error::Conflict)?;
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
        /// Bind already opaque originals; equal path data cannot create a Source
        /// or replace the complete pinned signed proof and current original checks.
        fn require_runtime_binding(
            &self,
            owner: &Arc<MutationGuard>,
            identity: &EngineIdentity,
            installation_root: &Path,
            directory: &Path,
            executable: &Path,
        ) -> Result<()> {
            if !Arc::ptr_eq(&self.owner, owner)
                || &self.identity != identity
                || self.installation.root != installation_root
                || self.directory != directory
                || self.executable != executable
            {
                return Err(Error::Conflict);
            }
            Ok(())
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
        /// Compare immutable originals only. This does not authenticate current
        /// signed payloads or the DLL pin and cannot grant mapping/effect authority.
        pub(in crate::windows) fn require_runtime_binding(
            &self,
            owner: &Arc<MutationGuard>,
            identity: &EngineIdentity,
            installation_root: &Path,
            directory: &Path,
            executable: &Path,
        ) -> Result<()> {
            self.0.require_runtime_binding(
                owner,
                identity,
                installation_root,
                directory,
                executable,
            )
        }
        pub(in crate::windows) fn verify_runtime_binding(
            &self,
            owner: &Arc<MutationGuard>,
            identity: &EngineIdentity,
            installation_root: &Path,
            directory: &Path,
            executable: &Path,
        ) -> Result<()> {
            self.require_runtime_binding(
                owner,
                identity,
                installation_root,
                directory,
                executable,
            )?;
            self.0.verify()
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
            // The complete pinned signed proof covers BOTH slots and ALL
            // payloads. Join every original library to that SAME owner, root,
            // executable and manifest before/after current inventory checks.
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
                carrier
                    .payload
                    .verify_original()
                    .map_err(|_| Error::Conflict)?;
                for (library, kind) in self.libraries.iter().zip(&expected) {
                    // Both payload pins use the signed layout's path spelling;
                    // the kernel executable is canonical (verbatim on Windows).
                    if library.kind != *kind
                        || !Arc::ptr_eq(&library.owner, owner)
                        || library.identity() != carrier.identity()
                        || library.installation.root != carrier.installation.root
                        || library.directory != carrier.directory
                        || library.executable != carrier.executable
                        || library.payload.path()
                            != carrier.payload.path().with_file_name(kind.path())
                    {
                        return Err(Error::Conflict);
                    }
                    (library.root)()?;
                    library
                        .payload
                        .verify_original()
                        .map_err(|_| Error::Conflict)?;
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
        pub(in crate::windows) fn verify_runtime_binding(
            &self,
            owner: &Arc<MutationGuard>,
            identity: &EngineIdentity,
            installation_root: &Path,
            directory: &Path,
            executable: &Path,
        ) -> Result<()> {
            self.carrier.0.require_runtime_binding(
                owner,
                identity,
                installation_root,
                directory,
                executable,
            )?;
            // Retain all member kind/path/root/owner/DLL pin comparisons before
            // and after the carrier's current complete installed-proof checks.
            self.verify_owner(owner)
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
        let (manifest, _) = read_signed_manifest(directory, identity)?;
        library_entry(&manifest, &identity.manifest_sha256, identity, kind)
    }
    fn read_signed_manifest(
        directory: &Path,
        identity: &EngineIdentity,
    ) -> Result<(VerifiedContainerManifest, u64)> {
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
        if d::digest(&bytes) != identity.manifest_sha256 {
            return Err(Error::Conflict);
        }
        Ok((manifest, bytes.len() as u64))
    }

    #[cfg(test)]
    mod installed_runtime_native_tests {
        use super::*;

        #[test]
        fn installed_runtime_pins_every_authenticated_dependency_until_drop() {
            use ed25519_dalek::{Signer, SigningKey};
            use std::collections::BTreeSet;
            let fixture = super::super::super::member_carrier_factory_test_os::Fixture::new()
                .expect("actual private signed fixture");
            let executable = actual_executable().unwrap();
            let root = fixture.original_root();
            let installation =
                super::super::super::member_carrier_factory_test_os::installation(root)
                    .expect("signed installation registered for the fixture's original root");
            let initial = installation.load_engine(&executable).unwrap();
            let directory = &initial.directory;
            // Stage a real signed second slot in our owned fixture. The expected
            // inventory below uses fixed fixture paths, not verifier enumeration.
            let names = [
                "nelomai-windows-service.exe",
                "wintun.dll",
                "wireguard.dll",
                "tunnel.dll",
                "amneziawg-tunnel.dll",
            ];
            let stable = directory.join("engines/stable/0.3.2");
            std::fs::create_dir_all(&stable).unwrap();
            for name in names {
                std::fs::copy(
                    directory.join("engines/latest/0.3.3").join(name),
                    stable.join(name),
                )
                .unwrap();
            }
            let mut manifest: serde_json::Value =
                serde_json::from_slice(&std::fs::read(directory.join(d::MANIFEST_NAME)).unwrap())
                    .unwrap();
            let mut slot = manifest["slots"][0].clone();
            slot["slot"] = "stable".into();
            slot["manifest"]["runtime_version"] = "0.3.2".into();
            manifest["slots"].as_array_mut().unwrap().push(slot);
            manifest["stable_release_set_sha256"] = "b".repeat(64).into();
            manifest["stable_platform_manifest_sha256"] = "c".repeat(64).into();
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let message = [
                nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
                &bytes,
            ]
            .concat();
            let key = SigningKey::from_bytes(&[83; 32]);
            let signature = key.sign(&message).to_bytes();
            nelomai_contracts::verify_container_manifest(
                &bytes,
                &signature,
                &key.verifying_key().to_bytes(),
                "windows",
                "x86_64",
            )
            .expect("signed two-slot fixture must satisfy distinct Stable manifest schema before pinning");
            std::fs::write(directory.join(d::MANIFEST_NAME), &bytes).unwrap();
            std::fs::write(directory.join(d::SIGNATURE_NAME), signature).unwrap();
            let policy_path = directory.join("installation-policy.json");
            let mut policy: d::BrokerPolicy =
                serde_json::from_slice(&std::fs::read(&policy_path).unwrap()).unwrap();
            policy.manifest_sha256 = d::digest(&bytes);
            std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
            let mut expected = BTreeSet::from([
                root.join("container-manifest.json"),
                directory.join("container-manifest-v1.json"),
                directory.join("container-manifest-v1.sig"),
                policy_path,
                directory
                    .join("dispatcher")
                    .join("1")
                    .join("nelomai-windows-service.exe"),
                policy.executable,
            ]);
            for relative in ["engines/latest/0.3.3", "engines/stable/0.3.2"] {
                for name in names {
                    expected.insert(directory.join(relative).join(name));
                }
            }
            let owner = Arc::new(MutationGuard::at(&root.join("engine-owner.lock")).unwrap());
            let pinned = PinnedInstalledRuntime::new(
                &installation,
                &executable,
                owner,
                InstalledRuntimeOrigin::Source,
            )
            .unwrap();
            pinned.verify().unwrap();
            assert_eq!(
                pinned
                    .files
                    .paths()
                    .map(Path::to_path_buf)
                    .collect::<BTreeSet<_>>(),
                expected
            );
            for path in &expected {
                assert!(std::fs::OpenOptions::new().write(true).open(path).is_err());
                assert!(std::fs::rename(path, path.with_extension("renamed")).is_err());
                assert!(std::fs::remove_file(path).is_err());
            }
            let pointer = root.join(d::POINTER_NAME);
            drop(pinned);
            let bytes = std::fs::read(&pointer).unwrap();
            std::fs::write(pointer, bytes).unwrap();
        }

        #[test]
        fn installed_runtime_acquisition_rejects_payload_drift_after_initial_authentication() {
            let fixture = super::super::super::member_carrier_factory_test_os::Fixture::new()
                .expect("actual private signed fixture");
            let executable = actual_executable().unwrap();
            let root = fixture.original_root();
            let installation =
                super::super::super::member_carrier_factory_test_os::installation(root)
                    .expect("signed installation registered for the fixture's original root");
            let owner = Arc::new(MutationGuard::at(&root.join("engine-owner.lock")).unwrap());
            let pristine = PinnedInstalledRuntime::new(
                &installation,
                &executable,
                owner.clone(),
                InstalledRuntimeOrigin::Source,
            )
            .expect("pristine signed fixture must successfully pin before testing payload drift");
            drop(pristine);
            let layout = installation.load_engine(&executable).unwrap();
            let path = layout.engine_path().with_file_name("tunnel.dll");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[0] ^= 1; // Same length; metadata cannot authenticate this drift.
            std::fs::write(&path, bytes).unwrap();
            assert!(PinnedInstalledRuntime::acquire_after_authentication(
                &installation,
                &executable,
                owner,
                layout,
                InstalledRuntimeOrigin::Source,
            )
            .is_err());
            assert!(std::fs::OpenOptions::new().write(true).open(path).is_ok());
        }
    }
}

#[cfg(test)]
#[path = "member_carrier_payload_tests.rs"]
mod tests;
