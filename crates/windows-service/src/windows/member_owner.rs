//! Native SCM/proof adapter owned by the authenticated pair factory.
//!
//! Journal and PrivateConfig come from MemberFiles: private ancestors/ACLs,
//! pinned handle identity, no reparse or multi-link files, atomic digest CAS
//! and synced publication/readback. The legacy private write helper is not a
//! fallback. dispatcher::trusted() alone does not supply these file guarantees.
//!
//! The enclosing trusted owner holds its privileged slot mutation/lifecycle lock
//! across inspect/effect/readback. SCM offers no atomic config+PID+IF CAS against
//! other privileged writers. No routes, DNS, sibling slot or file cleanup here.

#[cfg(test)]
use super::install::finish_created_slot_service;
use super::install::{
    create_fresh_slot_service, engine_primitive, open_slot_service, slot_config_path,
    wait_until_stopped,
};
use crate::member_owner::{
    Intent, InterfaceProof, MemberIo, NativeProof, Observation, OriginalMemberFacts,
    OriginalMemberNative, OriginalMemberPin, OriginalMemberPinSource, OriginalMemberRebindIo,
    OriginalMemberStartNative, OriginalRebindAck, OwnerError, ProcessProof, Record, Result,
    RetainedMemberOrigin, ServiceObservation,
};
use crate::member_owner::{
    OriginalMemberPartialCleanupIo, OriginalServiceCleanup, OriginalServiceCleanupNative,
    PartialServiceObservation, ServiceCleanupFacts, ServiceCleanupState,
};
use crate::redundancy::{slot_service_name, slot_service_spec};
use nelomai_client_tunnel::TunnelTransport;
use nelomai_contracts::dispatcher::{EnginePrimitive, TunnelSlot};
use std::{
    ffi::OsString,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_service::service::{
    Service, ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceSidType,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_INVALID_PARAMETER, FILETIME},
    NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
    System::Threading::{
        GetExitCodeProcess, GetProcessId, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    },
    UI::Shell::CommandLineToArgvW,
};

pub(crate) use super::member_carrier_payload::native::{MemberSource, WintunSource};
use super::member_files::{pin_runtime_payload, PinnedPayload};
use crate::member_owner::cold_wireguard_data::{Error as PackageError, Result as PackageResult};
use std::rc::Rc;

/// SAME original signed member Source plus supplementary DATA handles. These
/// handles cannot replace the Source's owner/ACK or load any executable. The
/// Source's original no-write/no-delete pins prevent replacement across this
/// independently signed-manifest-to-DATA-pin bracket. No caller path/hash.
pub(crate) struct NativeWireGuardSource {
    source: Rc<MemberSource>,
    carrier: Rc<WintunSource>,
    files: [PinnedPayload; 2],
}

/// Original signed backend and factual process-local cold module absence.
/// Not ownership/lifetime of a module in the NEW member service process, nor
/// permission to execute/load/install. Unknown/previously loaded images deny.
pub(crate) fn verify_readonly_cold_backend_modules(
    source: &Rc<MemberSource>,
    carrier: &Rc<WintunSource>,
) -> PackageResult<()> {
    use windows_sys::Win32::{
        Foundation::ERROR_MOD_NOT_FOUND, System::LibraryLoader::GetModuleHandleW,
    };
    source.verify().map_err(|_| PackageError::Changed)?;
    if !source.matches_carrier(carrier) {
        return Err(PackageError::Changed);
    }
    crate::member_owner::cold_wireguard_data::verify_cold_backend_modules(
        source.transport(),
        |name| {
            let name = name.encode_utf16().chain([0]).collect::<Vec<_>>();
            if !unsafe { GetModuleHandleW(name.as_ptr()) }.is_null() {
                return Ok(Some(()));
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_MOD_NOT_FOUND {
                return Err(PackageError::Native("cold module query", error));
            }
            Ok(None)
        },
    )?;
    source.verify().map_err(|_| PackageError::Changed)
}
impl NativeWireGuardSource {
    pub(crate) fn new(
        source: &Rc<MemberSource>,
        carrier: &Rc<WintunSource>,
    ) -> PackageResult<Self> {
        source.verify().map_err(|_| PackageError::Changed)?;
        if source.transport() != TunnelTransport::WireGuard || !source.matches_carrier(carrier) {
            return Err(PackageError::Changed);
        }
        let directory = carrier
            .path()
            .map_err(|_| PackageError::Changed)?
            .parent()
            .ok_or(PackageError::Changed)?
            .to_owned();
        let manifest = Self::manifest(source, carrier)?;
        let pin = |name: &str| {
            let selected = manifest
                .selected(source.identity().slot)
                .ok_or(PackageError::Changed)?;
            let entry = selected
                .files
                .iter()
                .find(|f| f.path == name)
                .filter(|f| {
                    f.role == nelomai_contracts::RuntimeFileRole::SharedLibrary
                        && f.size_bytes > 0
                        && f.size_bytes <= 16 * 1024 * 1024
                })
                .ok_or(PackageError::Changed)?;
            pin_runtime_payload(&directory.join(name), entry.size_bytes, &entry.sha256)
                .map_err(|_| PackageError::Changed)
        };
        let files = [pin("wireguard.dll")?, pin("tunnel.dll")?];
        let original = Self {
            source: source.clone(),
            carrier: carrier.clone(),
            files,
        };
        original.verify()?;
        Ok(original)
    }
    fn manifest(
        source: &MemberSource,
        carrier: &WintunSource,
    ) -> PackageResult<nelomai_contracts::VerifiedContainerManifest> {
        use nelomai_contracts::dispatcher as d;
        let directory = carrier
            .manifest_directory()
            .map_err(|_| PackageError::Changed)?;
        let bytes = d::read_bounded(&directory.join(d::MANIFEST_NAME), 1024 * 1024)
            .map_err(|_| PackageError::Changed)?;
        let signature = d::read_bounded(&directory.join(d::SIGNATURE_NAME), 64)
            .map_err(|_| PackageError::Changed)?;
        #[cfg(test)]
        let key = super::member_carrier_factory_test_os::key(directory)
            .map(Ok)
            .unwrap_or_else(d::pinned_key)
            .map_err(|_| PackageError::Changed)?;
        #[cfg(not(test))]
        let key = d::pinned_key().map_err(|_| PackageError::Changed)?;
        let manifest = nelomai_contracts::verify_container_manifest(
            &bytes, &signature, &key, "windows", "x86_64",
        )
        .map_err(|_| PackageError::Changed)?;
        let selected = manifest
            .selected(source.identity().slot)
            .ok_or(PackageError::Changed)?;
        let identity = source.identity();
        if identity.manifest_sha256 != d::digest(&bytes)
            || identity.container_version != manifest.manifest().container_version
            || identity.runtime_version != selected.runtime_version
            || identity.runtime_contract_version != selected.contract_version
        {
            return Err(PackageError::Changed);
        }
        Ok(manifest)
    }
    pub(crate) fn verify(&self) -> PackageResult<()> {
        self.source.verify().map_err(|_| PackageError::Changed)?;
        if !self.source.matches_carrier(&self.carrier)
            || self.source.transport() != TunnelTransport::WireGuard
        {
            return Err(PackageError::Changed);
        }
        let directory = self
            .carrier
            .path()
            .map_err(|_| PackageError::Changed)?
            .parent()
            .ok_or(PackageError::Changed)?;
        Self::manifest(&self.source, &self.carrier)?;
        for (file, name) in self.files.iter().zip(["wireguard.dll", "tunnel.dll"]) {
            if file.path() != directory.join(name) {
                return Err(PackageError::Changed);
            }
            file.verify().map_err(|_| PackageError::Changed)?;
        }
        self.source.verify().map_err(|_| PackageError::Changed)
    }
    pub(crate) fn file(&self) -> PackageResult<&std::fs::File> {
        self.verify()?;
        Ok(self.files[0].file())
    }
    pub(crate) fn matches_original(
        &self,
        source: &Rc<MemberSource>,
        carrier: &Rc<WintunSource>,
    ) -> bool {
        Rc::ptr_eq(&self.source, source) && Rc::ptr_eq(&self.carrier, carrier)
    }
}

/// Implemented by the protected MemberFiles native file boundary.
/// A returned digest is a proof of the SAME still-private file, not fs::read by
/// path following an earlier ACL check. Errors must never include file contents.
pub(crate) trait PrivateConfig {
    fn read_digest(&mut self, path: &Path) -> Result<Option<[u8; 32]>>;
    /// Exact digest CAS under the same private-file lock and publication handle.
    /// No read-then-write fallback: the protected MemberFiles adapter supplies it.
    fn replace_atomically(
        &mut self,
        _path: &Path,
        _expected_sha256: Option<[u8; 32]>,
        _canonical: &str,
    ) -> Result<()> {
        Err(OwnerError::Native)
    }
}

pub(crate) struct NativeMemberIo<F> {
    engine: PathBuf,
    slot: TunnelSlot,
    transport: TunnelTransport,
    config_path: PathBuf,
    files: F,
    cleanup_only: bool,
    original: RetainedMemberOrigin<Service, OwnedHandle>,
}
impl<F: PrivateConfig> NativeMemberIo<F> {
    /// Trusted factory only. Caller authenticates and canonicalizes engine from
    /// installed layout, never from an app request. Does not create any objects.
    pub(crate) fn from_trusted_factory(
        engine: PathBuf,
        slot: TunnelSlot,
        transport: TunnelTransport,
        files: F,
    ) -> Result<Self> {
        if !engine.is_absolute() || engine.to_str().is_none() {
            return Err(OwnerError::Invalid);
        }
        if std::fs::canonicalize(&engine).map_err(|_| OwnerError::Native)? != engine {
            return Err(OwnerError::Invalid);
        }
        let config_path = slot_config_path(slot).map_err(|_| OwnerError::Native)?;
        Ok(Self {
            engine,
            slot,
            transport,
            config_path,
            files,
            cleanup_only: false,
            original: RetainedMemberOrigin::empty(),
        })
    }
    /// A terminal retained journal may outlive its installed engine directory.
    /// Use its path only for exact SCM command-line comparison; this adapter
    /// cannot start/rebind a service or rewrite a configuration.
    pub(crate) fn for_retained_cleanup(record: &Record, files: F) -> Result<Self> {
        crate::member_owner::validate_record_shape(record)?;
        Ok(Self {
            engine: record.intent.engine.clone(),
            slot: record.intent.slot,
            transport: record.intent.transport,
            config_path: slot_config_path(record.intent.slot).map_err(|_| OwnerError::Native)?,
            files,
            cleanup_only: true,
            original: RetainedMemberOrigin::empty(),
        })
    }
    fn bound(&self, intent: &Intent) -> Result<()> {
        if self.engine != intent.engine
            || self.slot != intent.slot
            || self.transport != intent.transport
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    /// Factual SCM/process/interface read pin only. The owner-facing acquisition
    /// first runs original_live().read(); this method grants no private-file,
    /// durable/runtime/auth, native NIC/source, or mutation authority.
    #[allow(dead_code)] // Common creator composition consumes this separately.
    pub(crate) fn original_read_pin(&mut self) -> Result<OriginalMemberReadPin> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        Ok(OriginalMemberReadPin {
            pin: self.original.pin()?,
        })
    }
    pub(crate) fn service_domain_for_cleanup(
        &mut self,
        intent: &Intent,
        retained: &NativeProof,
    ) -> Result<(Observation, Option<crate::member_owner::ServiceDomain>)> {
        self.original.revoke();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(intent)?;
        let files = &mut self.files;
        let path = &self.config_path;
        self.original.inspect_original_for_cleanup_with(
            &mut NativeOriginalCalls { files: None },
            intent,
            retained,
            || files.read_digest(path),
            read_service_domain,
        )
    }
    fn inspect_once(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation> {
        self.bound(intent)?;
        self.observe_once(retained)
    }
    /// Read-only empty-claim recovery: does not invent an Intent/proof and
    /// cannot authorize a mutation. Both service variants and interface aliases
    /// are checked; the factory also requires absent protected owner journals.
    pub(crate) fn observe_unclaimed(&mut self) -> Result<Observation> {
        let before = self.observe_once(None)?;
        if self.observe_once(None)? != before {
            return Err(OwnerError::Conflict);
        }
        Ok(before)
    }
    fn observe_once(&mut self, retained: Option<&NativeProof>) -> Result<Observation> {
        let config_sha256 = self.files.read_digest(&self.config_path)?;
        let service = match open_slot_service(
            self.slot,
            self.transport,
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| OwnerError::Native)?
        {
            None => None,
            Some(service) => {
                let actual = service.query_config().map_err(|_| OwnerError::Native)?;
                let expected =
                    slot_service_spec(&self.engine, &self.config_path, self.slot, self.transport)
                        .map_err(|_| OwnerError::Invalid)?;
                let mut argv = vec![self.engine.as_os_str().to_owned()];
                argv.extend(expected.arguments.iter().map(OsString::from));
                // QueryServiceConfig's executable_path is the complete raw SCM
                // command line. Compare every decoded argument, not a prefix or
                // basename; additional switches/alternate paths are foreign.
                let exact_spec = command_arguments(actual.executable_path.as_os_str())? == argv
                    && actual.start_type == ServiceStartType::OnDemand
                    && actual.service_type == ServiceType::OWN_PROCESS
                    && actual.account_name.as_deref() == Some(std::ffi::OsStr::new("LocalSystem"));
                let status = service.query_status().map_err(|_| OwnerError::Native)?;
                let process = match status.current_state {
                    ServiceState::Stopped => None,
                    ServiceState::Running => Some(process_proof(
                        status
                            .process_id
                            .filter(|p| *p != 0)
                            .ok_or(OwnerError::Native)?,
                    )?),
                    _ => return Err(OwnerError::Pending),
                };
                Some(ServiceObservation {
                    exact_spec,
                    process,
                })
            }
        };
        let alternative_service_present = open_slot_service(
            self.slot,
            other(self.transport),
            ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| OwnerError::Native)?
        .is_some();
        let (interface, retained_interfaces) = interfaces(self.slot, self.transport, retained)?;
        if let Some(old) = retained {
            if service.as_ref().and_then(|s| s.process) != Some(old.process) {
                crate::member_owner::require_retired_process_absent(
                    &old.process,
                    query_process(old.process.pid)?,
                )?;
            }
        }
        Ok(Observation {
            config_sha256,
            service,
            alternative_service_present,
            interface,
            retained_interfaces,
        })
    }
    fn require_same(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        if &self.inspect(intent, retained)? != expected {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}
impl<F: PrivateConfig> MemberIo for NativeMemberIo<F> {
    fn revoke_original(&mut self) {
        self.original.revoke();
    }
    fn inspect_original(&mut self, intent: &Intent, retained: &NativeProof) -> Result<Observation> {
        if self.cleanup_only {
            self.original.revoke();
            return Err(OwnerError::Retired);
        }
        if let Err(error) = self.bound(intent) {
            self.original.revoke();
            return Err(error);
        }
        let files = &mut self.files;
        let path = &self.config_path;
        self.original.inspect_original(
            &mut NativeOriginalCalls { files: None },
            intent,
            retained,
            || files.read_digest(path),
        )
    }
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        let before = self.inspect_once(intent, retained)?;
        if self.inspect_once(intent, retained)? != before {
            return Err(OwnerError::Conflict);
        }
        Ok(before)
    }
    fn inspect_original_for_cleanup(
        &mut self,
        intent: &Intent,
        retained: &NativeProof,
    ) -> Result<Observation> {
        self.original.revoke();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(intent)?;
        let files = &mut self.files;
        let path = &self.config_path;
        self.original.inspect_original_for_cleanup(
            &mut NativeOriginalCalls { files: None },
            intent,
            retained,
            || files.read_digest(path),
        )
    }
    fn write_private_config(
        &mut self,
        intent: &Intent,
        expected_sha256: Option<[u8; 32]>,
        canonical: &str,
    ) -> Result<()> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(intent)?;
        self.files
            .replace_atomically(&self.config_path, expected_sha256, canonical)?;
        if self.files.read_digest(&self.config_path)? != Some(intent.config_sha256) {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    fn start_fresh(&mut self, intent: &Intent, retired: Option<&NativeProof>) -> Result<()> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        let current = self.inspect(intent, retired)?;
        if current.service.is_some()
            || current.alternative_service_present
            || current.interface.is_some()
            || !current.retained_interfaces.is_empty()
            || current.config_sha256 != Some(intent.config_sha256)
        {
            return Err(OwnerError::Conflict);
        }
        self.original.start_retaining_process(
            &mut NativeOriginalCalls {
                files: Some(&mut self.files),
            },
            intent,
        )
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        self.original.revoke();
        self.require_same(intent, retained, expected)?;
        if self.original.creation_attempted() {
            return self.original.stop_delete(
                &mut NativeOriginalCalls {
                    files: Some(&mut self.files),
                },
                intent,
                retained,
                expected,
            );
        }
        // Existing cleanup-only/recovery path supplies no original receipt.
        engine_primitive(EnginePrimitive::StopSlot { slot: self.slot }, &self.engine)
            .map_err(|_| OwnerError::Native)
    }
    fn rebind(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
        expected: &Observation,
    ) -> Result<()> {
        self.original.revoke();
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.require_same(intent, Some(proof), expected)?;
        let action = match self.transport {
            TunnelTransport::WireGuard => EnginePrimitive::RebindWireguardSlot { slot: self.slot },
            TunnelTransport::AmneziaWg3 => EnginePrimitive::RebindAmneziawgSlot { slot: self.slot },
        };
        engine_primitive(action, &self.engine).map_err(|_| OwnerError::Native)
    }
}

impl<F: PrivateConfig> OriginalMemberPinSource for NativeMemberIo<F> {
    type Pin = OriginalMemberReadPin;
    fn original_read_pin(&mut self) -> Result<Self::Pin> {
        NativeMemberIo::original_read_pin(self)
    }
}
impl<F: PrivateConfig> OriginalMemberPartialCleanupIo for NativeMemberIo<F> {
    type CleanupPin = OriginalServiceCleanup<Service, OwnedHandle>;
    fn partial_cleanup_pin(&mut self, intent: &Intent) -> Result<Self::CleanupPin> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(intent)?;
        self.original.partial_cleanup_pin(intent)
    }
    fn inspect_partial_cleanup(
        &mut self,
        pin: &Self::CleanupPin,
    ) -> Result<PartialServiceObservation> {
        if self.cleanup_only || !pin.matches_origin(&self.original) {
            return Err(OwnerError::Retired);
        }
        let files = &mut self.files;
        let path = &self.config_path;
        pin.inspect(&mut NativeOriginalCalls { files: None }, || {
            files.read_digest(path).inspect_err(|_error| {
                #[cfg(all(windows, test))]
                eprintln!("actual original partial config read: {_error:?}");
            })
        })
    }
    fn stop_partial_original(
        &mut self,
        pin: &Self::CleanupPin,
        retained: Option<&NativeProof>,
    ) -> Result<()> {
        if self.cleanup_only || !pin.matches_origin(&self.original) {
            return Err(OwnerError::Retired);
        }
        // Share the existing 15-second SCM Stop budget with factual rundown;
        // no second Stop/Delete or additional stacked wait is permitted.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let files = &mut self.files;
        let path = &self.config_path;
        pin.stop_delete(&mut NativeOriginalCalls { files: None }, || {
            files.read_digest(path)
        })?;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(OwnerError::Pending);
            }
            let before = match self.inspect_partial_cleanup(pin) {
                Err(OwnerError::Pending) => {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(OwnerError::Pending);
                    }
                    std::thread::sleep(remaining.min(std::time::Duration::from_millis(100)));
                    continue;
                }
                result => result?,
            };
            if !before.service_deleted() || before.process.is_none() {
                return Err(OwnerError::Pending);
            }
            if retained.is_some_and(|proof| before.process != Some(proof.process)) {
                return Err(OwnerError::Conflict);
            }
            let config = self.files.read_digest(&self.config_path)?;
            let actual = self.observe_once(retained)?;
            if self.inspect_partial_cleanup(pin)? != before
                || actual.config_sha256 != config
                || config.is_none()
                || actual.alternative_service_present
                || actual.service.is_some()
                || actual.retained_interfaces.len() > 1
                || actual.interface.is_some_and(|interface| {
                    retained.is_none_or(|proof| interface != proof.interface)
                })
                || actual
                    .retained_interfaces
                    .iter()
                    .any(|interface| retained.is_none_or(|proof| *interface != proof.interface))
            {
                return Err(OwnerError::Conflict);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(OwnerError::Pending);
            }
            if actual.interface.is_none() && actual.retained_interfaces.is_empty() {
                return Ok(()); // Final stable absence/current/CAS checks remain in MemberOwner.
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(100)));
        }
    }
}
impl<F: PrivateConfig> OriginalMemberRebindIo for NativeMemberIo<F> {
    fn rebind_original(
        &mut self,
        intent: &Intent,
        old: &NativeProof,
    ) -> Result<std::rc::Rc<OriginalRebindAck>> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(intent)?;
        let files = &mut self.files;
        let path = &self.config_path;
        self.original.rebind_original(
            &mut NativeOriginalCalls { files: None },
            intent,
            old,
            || files.read_digest(path),
        )
    }
    fn read_rebound_original(
        &mut self,
        ack: &std::rc::Rc<OriginalRebindAck>,
    ) -> Result<NativeProof> {
        if self.cleanup_only {
            return Err(OwnerError::Retired);
        }
        self.bound(ack.intent())?;
        let files = &mut self.files;
        let path = &self.config_path;
        self.original
            .read_rebound_original(&mut NativeOriginalCalls { files: None }, ack, || {
                files.read_digest(path)
            })
    }
}

/// Opaque SAME-origin factual read, with no F/private-config ownership. The
/// shared holder is cleared only by explicit acknowledged original deletion;
/// pins cannot extend the SCM handle past that close or perform native effects.
#[allow(dead_code)] // Main will compose this into the creator registry.
pub(crate) struct OriginalMemberReadPin {
    pin: OriginalMemberPin<Service, OwnedHandle>,
}
impl OriginalMemberReadPin {
    pub(crate) fn service_domain(
        &mut self,
    ) -> Result<(
        (Intent, NativeProof),
        Option<crate::member_owner::ServiceDomain>,
    )> {
        self.pin.inspect(
            &mut NativeOriginalCalls { files: None },
            read_service_domain,
        )
    }
    #[allow(dead_code)]
    pub(crate) fn read(&mut self) -> Result<(Intent, NativeProof)> {
        self.pin.read(&mut NativeOriginalCalls { files: None })
    }
}

struct NativeOriginalCalls<'a> {
    files: Option<&'a mut dyn PrivateConfig>,
}
impl OriginalMemberStartNative for NativeOriginalCalls<'_> {
    fn configure_created(&mut self, service: &Service, intent: &Intent) -> Result<()> {
        let before = held_service_identity(service, intent, false)?;
        if before != (true, 0) {
            return Err(OwnerError::Conflict);
        }
        let path = slot_config_path(intent.slot).map_err(|_| OwnerError::Native)?;
        if self
            .files
            .as_mut()
            .ok_or(OwnerError::Pending)?
            .read_digest(&path)?
            != Some(intent.config_sha256)
        {
            return Err(OwnerError::Conflict);
        }
        service
            .set_config_service_sid_info(ServiceSidType::Unrestricted)
            .map_err(|_| OwnerError::Native)?;
        if held_service_identity(service, intent, true)? != before {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
    fn start_created(&mut self, service: &Service) -> Result<()> {
        // Start ACK ONLY. No installation mutex is acquired/held over the child
        // StartService call, and no fallible wait/postflight hides its outputs.
        service
            .start(&[] as &[&str])
            .map_err(|_| OwnerError::Native)
    }
    fn first_running_pid(&mut self, service: &Service) -> Result<u32> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(OwnerError::Pending);
            }
            let status = service.query_status().map_err(|_| OwnerError::Native)?;
            if status.service_type != ServiceType::OWN_PROCESS {
                return Err(OwnerError::Conflict);
            }
            use crate::member_owner::{original_start_process_pid, OriginalServiceStartStatus};
            let sample = match status.current_state {
                ServiceState::Running => OriginalServiceStartStatus::Running(status.process_id),
                ServiceState::StartPending => {
                    OriginalServiceStartStatus::StartPending(status.process_id)
                }
                ServiceState::Stopped | ServiceState::StopPending => {
                    OriginalServiceStartStatus::Stopped
                }
                _ => OriginalServiceStartStatus::Other,
            };
            if let Some(pid) = original_start_process_pid(sample)? {
                // Return immediately to root; no extra SCM query/capture first.
                return Ok(pid);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    fn finish_started(
        &mut self,
        service: &Service,
        process: &OwnedHandle,
        birth: &ProcessProof,
        intent: &Intent,
    ) -> Result<()> {
        let path = slot_config_path(intent.slot).map_err(|_| OwnerError::Native)?;
        for _ in 0..2 {
            if self
                .files
                .as_mut()
                .ok_or(OwnerError::Pending)?
                .read_digest(&path)?
                != Some(intent.config_sha256)
                || held_service_identity(service, intent, true)? != (true, birth.pid)
                || query_process_handle(process)? != (*birth, 259)
            {
                return Err(OwnerError::Conflict);
            }
            verify_started_process_image(process, &intent.engine)?;
        }
        if self
            .files
            .as_mut()
            .ok_or(OwnerError::Pending)?
            .read_digest(&path)?
            != Some(intent.config_sha256)
        {
            return Err(OwnerError::Conflict);
        }
        Ok(())
    }
}

fn verify_started_process_image(process: &OwnedHandle, original: &Path) -> Result<()> {
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
        || length == 0
        || length as usize >= image.len()
    {
        return Err(OwnerError::Native);
    }
    let actual = PathBuf::from(OsString::from_wide(&image[..length as usize]));
    if std::fs::canonicalize(actual).map_err(|_| OwnerError::Native)? != original {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}
fn read_service_domain(
    intent: &Intent,
    process: &OwnedHandle,
) -> Result<Option<crate::member_owner::ServiceDomain>> {
    use windows_sys::Win32::{
        NetworkManagement::WindowsFilteringPlatform::{
            FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB,
        },
        Security::{
            GetTokenInformation, LookupAccountNameW, TokenGroups, TOKEN_GROUPS, TOKEN_QUERY,
        },
        System::{
            SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
            Threading::OpenProcessToken,
        },
    };
    if intent.transport != TunnelTransport::WireGuard {
        return Ok(None);
    }
    verify_started_process_image(process, &intent.engine)?;
    let account: Vec<u16> = format!(
        "NT SERVICE\\{}",
        slot_service_name(intent.slot, intent.transport)
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let mut sid = [0u64; 4]; // SID authority NT, six subauthorities: exactly 32 bytes.
    let mut sid_size = 32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut sid_use = 0;
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    } == 0
        || sid_size != 32
    {
        return Err(OwnerError::Native);
    }
    let service_sid = unsafe { std::slice::from_raw_parts(sid.as_ptr().cast::<u8>(), 32) }.to_vec();
    if service_sid[..8] != [1, 6, 0, 0, 0, 0, 0, 5] || service_sid[8..12] != 80u32.to_le_bytes() {
        return Err(OwnerError::Conflict);
    }
    let mut raw_token = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw_token) } == 0
        || raw_token.is_null()
    {
        return Err(OwnerError::Native);
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut needed = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed < std::mem::size_of::<TOKEN_GROUPS>() as u32 || needed > 32768 {
        return Err(OwnerError::Conflict);
    }
    let mut groups = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = groups.len() * std::mem::size_of::<usize>();
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenGroups,
            groups.as_mut_ptr().cast(),
            capacity as u32,
            &mut needed,
        )
    } == 0
        || needed as usize > capacity
    {
        return Err(OwnerError::Native);
    }
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if (needed as usize) < offset {
        return Err(OwnerError::Conflict);
    }
    let header = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let count = header.GroupCount as usize;
    if count > 1024
        || offset + count * std::mem::size_of::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>()
            > needed as usize
    {
        return Err(OwnerError::Conflict);
    }
    let entries = unsafe {
        std::slice::from_raw_parts(
            groups
                .as_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<windows_sys::Win32::Security::SID_AND_ATTRIBUTES>(),
            count,
        )
    };
    let start = groups.as_ptr() as usize;
    let end = start
        .checked_add(needed as usize)
        .ok_or(OwnerError::Conflict)?;
    let mut enabled = false;
    for group in entries {
        let address = group.Sid as usize;
        if address < start || address.checked_add(8).is_none_or(|p| p > end) {
            return Err(OwnerError::Conflict);
        }
        let prefix = unsafe { std::slice::from_raw_parts(group.Sid.cast::<u8>(), 8) };
        let size = 8 + 4 * usize::from(prefix[1]);
        if prefix[0] != 1 || prefix[1] > 15 || address.checked_add(size).is_none_or(|p| p > end) {
            return Err(OwnerError::Conflict);
        }
        let actual = unsafe { std::slice::from_raw_parts(group.Sid.cast::<u8>(), size) };
        if actual == service_sid
            && group.Attributes & SE_GROUP_ENABLED as u32 != 0
            && group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
        {
            enabled = true;
        }
    }
    if !enabled {
        return Err(OwnerError::Conflict);
    }
    let image: Vec<u16> = intent
        .engine
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut raw: *mut FWP_BYTE_BLOB = ptr::null_mut();
    let status = unsafe { FwpmGetAppIdFromFileName0(image.as_ptr(), &mut raw) };
    let bytes = match unsafe { raw.as_ref() } {
        Some(blob)
            if status == 0
                && blob.size >= 4
                && blob.size <= 32768
                && blob.size % 2 == 0
                && !blob.data.is_null() =>
        {
            Some(unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec())
        }
        _ => None,
    };
    if !raw.is_null() {
        unsafe {
            FwpmFreeMemory0((&mut raw as *mut *mut FWP_BYTE_BLOB).cast());
        }
    }
    let bytes = bytes.ok_or(OwnerError::Native)?;
    let app_id: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    if app_id.last() != Some(&0)
        || app_id[..app_id.len() - 1].contains(&0)
        || String::from_utf16(&app_id[..app_id.len() - 1]).is_err()
    {
        return Err(OwnerError::Conflict);
    }
    Ok(Some(crate::member_owner::ServiceDomain {
        app_id,
        service_sid,
    }))
}

impl OriginalMemberNative for NativeOriginalCalls<'_> {
    type Service = Service;
    type Process = OwnedHandle;

    fn create(&mut self, intent: &Intent) -> Result<Service> {
        create_fresh_slot_service(&intent.engine, intent.slot, intent.transport)
            .map_err(|_| OwnerError::Native)
    }
    #[cfg(test)]
    fn finish_created(&mut self, service: &Service) -> Result<()> {
        finish_created_slot_service(service).map_err(|_| OwnerError::Native)
    }
    fn running_pid(&mut self, service: &Service) -> Result<u32> {
        let status = service.query_status().map_err(|_| OwnerError::Native)?;
        if status.current_state != ServiceState::Running
            || status.service_type != ServiceType::OWN_PROCESS
        {
            return Err(OwnerError::Conflict);
        }
        status
            .process_id
            .filter(|pid| *pid != 0)
            .ok_or(OwnerError::Native)
    }
    fn pin_process(&mut self, pid: u32) -> Result<OwnedHandle> {
        open_process(pid)?.ok_or(OwnerError::Native)
    }
    fn query_process(&mut self, process: &OwnedHandle) -> Result<(ProcessProof, u32)> {
        query_process_handle(process)
    }
    fn observe(
        &mut self,
        service: &Service,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<OriginalMemberFacts> {
        held_native_facts(service, intent, retained, true)
    }
    fn observe_cleanup(
        &mut self,
        service: &Service,
        intent: &Intent,
        retained: Option<&NativeProof>,
    ) -> Result<Observation> {
        let path = slot_config_path(intent.slot).map_err(|_| OwnerError::Native)?;
        let files = self.files.as_mut().ok_or(OwnerError::Native)?;
        let config_sha256 = files.read_digest(&path)?;
        let facts = held_native_facts(service, intent, retained, false)?;
        let process = if facts.pid == 0 {
            None
        } else {
            Some(process_proof(facts.pid)?)
        };
        if files.read_digest(&path)? != config_sha256
            || held_native_facts(service, intent, retained, false)? != facts
        {
            return Err(OwnerError::Conflict);
        }
        if let Some(old) = retained {
            if process != Some(old.process) {
                crate::member_owner::require_retired_process_absent(
                    &old.process,
                    query_process(old.process.pid)?,
                )?;
            }
        }
        Ok(Observation {
            config_sha256,
            service: Some(ServiceObservation {
                exact_spec: facts.exact_spec,
                process,
            }),
            alternative_service_present: facts.alternative_service_present,
            interface: facts.interface,
            retained_interfaces: facts.retained_interfaces,
        })
    }
    fn stop(&mut self, service: &Service) -> Result<()> {
        if service
            .query_status()
            .map_err(|_| OwnerError::Native)?
            .current_state
            != ServiceState::Stopped
        {
            service.stop().map_err(|_| OwnerError::Native)?;
            wait_until_stopped(service).map_err(|_| OwnerError::Native)?;
        }
        Ok(())
    }
    fn start_existing(&mut self, service: &Service) -> Result<()> {
        service
            .start(&[] as &[&str])
            .map_err(|_| OwnerError::Native)?;
        super::install::wait_until_running(service).map_err(|_| OwnerError::Native)
    }
    fn delete(&mut self, service: &Service) -> Result<()> {
        service.delete().map_err(|_| OwnerError::Native)
    }
}
impl OriginalServiceCleanupNative for NativeOriginalCalls<'_> {
    fn verify_cleanup_process_image(
        &mut self,
        process: &OwnedHandle,
        intent: &Intent,
    ) -> Result<()> {
        verify_started_process_image(process, &intent.engine)
    }
    fn service_cleanup_facts(
        &mut self,
        service: &Service,
        intent: &Intent,
    ) -> Result<ServiceCleanupFacts> {
        // SAME acknowledged NEW SCM object. Before finish_created, SID may
        // still be None; this cleanup-only read gives no execution/live grant.
        let before = held_cleanup_service_identity(service, intent)?;
        let sid = service
            .get_config_service_sid_info()
            .map_err(|_| OwnerError::Native)?;
        if sid != ServiceSidType::None && sid != ServiceSidType::Unrestricted {
            return Err(OwnerError::Conflict);
        }
        let alternative_service_present = open_slot_service(
            intent.slot,
            other(intent.transport),
            ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| OwnerError::Native)?
        .is_some();
        if held_cleanup_service_identity(service, intent)? != before
            || service
                .get_config_service_sid_info()
                .map_err(|_| OwnerError::Native)?
                != sid
        {
            return Err(OwnerError::Conflict);
        }
        Ok(ServiceCleanupFacts {
            exact_spec: before.0,
            pid: before.2,
            state: before.1,
            alternative_service_present,
        })
    }
}

fn held_native_facts(
    service: &Service,
    intent: &Intent,
    retained: Option<&NativeProof>,
    require_sid: bool,
) -> Result<OriginalMemberFacts> {
    let before = held_service_identity(service, intent, require_sid)?;
    let (interface, retained_interfaces) = interfaces(intent.slot, intent.transport, retained)?;
    let alternative_service_present = open_slot_service(
        intent.slot,
        other(intent.transport),
        ServiceAccess::QUERY_STATUS,
    )
    .map_err(|_| OwnerError::Native)?
    .is_some();
    if held_service_identity(service, intent, require_sid)? != before {
        return Err(OwnerError::Conflict);
    }
    Ok(OriginalMemberFacts {
        exact_spec: before.0,
        pid: before.1,
        alternative_service_present,
        interface,
        retained_interfaces,
    })
}

fn held_service_identity(
    service: &Service,
    intent: &Intent,
    require_sid: bool,
) -> Result<(bool, u32)> {
    let exact_spec = held_service_spec(service, intent, require_sid)?;
    let status = service.query_status().map_err(|_| OwnerError::Native)?;
    if status.service_type != ServiceType::OWN_PROCESS {
        return Err(OwnerError::Conflict);
    }
    let pid = match status.current_state {
        ServiceState::Stopped => 0,
        ServiceState::Running => status
            .process_id
            .filter(|pid| *pid != 0)
            .ok_or(OwnerError::Native)?,
        _ => return Err(OwnerError::Pending),
    };
    Ok((exact_spec, pid))
}

/// SAME NEW SCM cleanup facts only. This does not alter ordinary/live identity
/// reads or authorize any process/NIC/row effect. A transitional/missing PID
/// cannot be pinned and never means Stopped or absent.
fn held_cleanup_service_identity(
    service: &Service,
    intent: &Intent,
) -> Result<(bool, ServiceCleanupState, u32)> {
    let exact_spec = held_service_spec(service, intent, false)?;
    let status = service.query_status().map_err(|_| OwnerError::Native)?;
    if status.service_type != ServiceType::OWN_PROCESS {
        return Err(OwnerError::Conflict);
    }
    let (state, pid) = match status.current_state {
        ServiceState::Stopped => (ServiceCleanupState::Stopped, 0),
        ServiceState::Running => (
            ServiceCleanupState::Running,
            status.process_id.filter(|pid| *pid != 0).unwrap_or(0),
        ),
        ServiceState::StartPending => (ServiceCleanupState::StartPending, 0),
        ServiceState::StopPending => (ServiceCleanupState::StopPending, 0),
        _ => return Err(OwnerError::Conflict),
    };
    Ok((exact_spec, state, pid))
}

fn held_service_spec(service: &Service, intent: &Intent, require_sid: bool) -> Result<bool> {
    let path = slot_config_path(intent.slot).map_err(|_| OwnerError::Native)?;
    let expected = slot_service_spec(&intent.engine, &path, intent.slot, intent.transport)
        .map_err(|_| OwnerError::Invalid)?;
    let actual = service.query_config().map_err(|_| OwnerError::Native)?;
    let mut argv = vec![intent.engine.as_os_str().to_owned()];
    argv.extend(expected.arguments.iter().map(OsString::from));
    let exact_spec = command_arguments(actual.executable_path.as_os_str())? == argv
        && actual.service_type == ServiceType::OWN_PROCESS
        && actual.start_type == ServiceStartType::OnDemand
        && actual.error_control == ServiceErrorControl::Normal
        && actual.load_order_group.is_none()
        && actual.tag_id == 0
        && actual.dependencies
            == expected
                .dependencies
                .iter()
                .map(|dependency| ServiceDependency::Service(OsString::from(dependency)))
                .collect::<Vec<_>>()
        && actual.account_name.as_deref() == Some(std::ffi::OsStr::new("LocalSystem"))
        && actual.display_name == OsString::from(expected.display_name)
        && (!require_sid
            || service
                .get_config_service_sid_info()
                .map_err(|_| OwnerError::Native)?
                == ServiceSidType::Unrestricted);
    Ok(exact_spec)
}

fn other(transport: TunnelTransport) -> TunnelTransport {
    match transport {
        TunnelTransport::WireGuard => TunnelTransport::AmneziaWg3,
        TunnelTransport::AmneziaWg3 => TunnelTransport::WireGuard,
    }
}
fn alias(slot: TunnelSlot, transport: TunnelTransport) -> &'static str {
    match transport {
        TunnelTransport::WireGuard => match slot {
            TunnelSlot::A => "nelomai-a",
            TunnelSlot::B => "nelomai-b",
        },
        TunnelTransport::AmneziaWg3 => slot_service_name(slot, transport),
    }
}

impl<F: PrivateConfig> crate::member_reboot::RebootIo for NativeMemberIo<F> {
    fn observe(&mut self, record: &Record) -> Result<Observation> {
        self.bound(&record.intent)?;
        // A fresh boot invalidates PID/index/LUID authority. GUIDs are used
        // solely to reject a still-present adapter, never to mutate that row.
        let before = self.observe_once(None)?;
        let (named, remaining) = interfaces_matching(self.slot, self.transport, |current| {
            [record.proof, record.retired_proof]
                .into_iter()
                .flatten()
                .any(|old| old.interface.guid == current.guid)
        })?;
        if named.is_some() || !remaining.is_empty() || self.observe_once(None)? != before {
            return Err(OwnerError::Conflict);
        }
        Ok(before)
    }
    fn remove_stopped(&mut self, record: &Record, before: &Observation) -> Result<()> {
        if <Self as crate::member_reboot::RebootIo>::observe(self, record)? != *before
            || before
                .service
                .as_ref()
                .is_none_or(|service| !service.exact_spec || service.process.is_some())
            || before.alternative_service_present
            || before.interface.is_some()
            || !before.retained_interfaces.is_empty()
            || before.config_sha256 != Some(record.intent.config_sha256)
        {
            return Err(OwnerError::Conflict);
        }
        // StopSlot only removes the exact on-demand SCM slot after the proof
        // above. No old executable is started and no native interface is adopted.
        engine_primitive(EnginePrimitive::StopSlot { slot: self.slot }, &self.engine)
            .map_err(|_| OwnerError::Native)
    }
}
fn process_proof(pid: u32) -> Result<ProcessProof> {
    match query_process(pid)? {
        Some((proof, 259)) => Ok(proof),
        _ => Err(OwnerError::Native),
    }
}
fn query_process(pid: u32) -> Result<Option<(ProcessProof, u32)>> {
    open_process(pid)?
        .as_ref()
        .map(query_process_handle)
        .transpose()
}
fn open_process(pid: u32) -> Result<Option<OwnedHandle>> {
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(OwnerError::Native)
        };
    }
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(raw) }))
}
fn query_process_handle(handle: &OwnedHandle) -> Result<(ProcessProof, u32)> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    let mut code = 0;
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
        || unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut code) } == 0
    {
        return Err(OwnerError::Native);
    }
    let creation_time = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    let pid = unsafe { GetProcessId(handle.as_raw_handle()) };
    if creation_time == 0 || pid == 0 {
        return Err(OwnerError::Native);
    }
    // An actual exit with numeric code STILL_ACTIVE must not look live.
    if code == 259 && (exited.dwHighDateTime != 0 || exited.dwLowDateTime != 0) {
        return Err(OwnerError::Conflict);
    }
    Ok((ProcessProof { pid, creation_time }, code))
}
struct IfTable(*mut MIB_IF_TABLE2);
impl Drop for IfTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}
fn interfaces(
    slot: TunnelSlot,
    transport: TunnelTransport,
    retained: Option<&NativeProof>,
) -> Result<(Option<InterfaceProof>, Vec<InterfaceProof>)> {
    interfaces_matching(slot, transport, |proof| {
        retained.is_some_and(|p| {
            p.interface.index == proof.index
                || p.interface.luid == proof.luid
                || p.interface.guid == proof.guid
        })
    })
}
fn interfaces_matching(
    slot: TunnelSlot,
    transport: TunnelTransport,
    matches_retained: impl Fn(&InterfaceProof) -> bool,
) -> Result<(Option<InterfaceProof>, Vec<InterfaceProof>)> {
    let mut raw = ptr::null_mut();
    let code = unsafe { GetIfTable2(&mut raw) };
    let table = IfTable(raw);
    if code != 0 || table.0.is_null() {
        return Err(OwnerError::Native);
    }
    let count = unsafe { ptr::addr_of!((*table.0).NumEntries).read() } as usize;
    if count > 4096 {
        return Err(OwnerError::Native);
    }
    let first = unsafe {
        ptr::addr_of!((*table.0).Table)
            .cast::<windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2>()
    };
    let rows = if count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(first, count) }
    };
    let mut selected = None;
    let mut kept = vec![];
    for row in rows {
        let end = row
            .Alias
            .iter()
            .position(|c| *c == 0)
            .ok_or(OwnerError::Native)?;
        let name = String::from_utf16(&row.Alias[..end]).map_err(|_| OwnerError::Native)?;
        if name.eq_ignore_ascii_case(alias(slot, other(transport))) {
            return Err(OwnerError::Conflict);
        }
        let g = row.InterfaceGuid;
        let mut guid = [0; 16];
        guid[..4].copy_from_slice(&g.data1.to_be_bytes());
        guid[4..6].copy_from_slice(&g.data2.to_be_bytes());
        guid[6..8].copy_from_slice(&g.data3.to_be_bytes());
        guid[8..].copy_from_slice(&g.data4);
        let proof = InterfaceProof {
            index: row.InterfaceIndex,
            luid: unsafe { row.InterfaceLuid.Value },
            guid,
        };
        if name.eq_ignore_ascii_case(alias(slot, transport)) && selected.replace(proof).is_some() {
            return Err(OwnerError::Conflict);
        }
        if matches_retained(&proof) {
            kept.push(proof);
        }
    }
    Ok((selected, kept))
}

/// Reboot cleanup checks GUID absence only. Reused numeric identifiers confer
/// no authority and are neither queried individually nor changed.
pub(crate) fn require_reboot_guids_absent(slot: TunnelSlot, guids: &[[u8; 16]]) -> Result<()> {
    let (named, remaining) = interfaces_matching(slot, TunnelTransport::WireGuard, |p| {
        guids.contains(&p.guid)
    })?;
    if named.is_some() || !remaining.is_empty() {
        return Err(OwnerError::Conflict);
    }
    Ok(())
}
struct LocalArgv(*mut windows_sys::core::PWSTR);
impl Drop for LocalArgv {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0.cast()) };
    }
}
pub(crate) fn command_arguments(command: &std::ffi::OsStr) -> Result<Vec<OsString>> {
    let mut wide: Vec<u16> = command.encode_wide().collect();
    if wide.is_empty() || wide.len() > 32767 || wide.contains(&0) {
        return Err(OwnerError::Conflict);
    }
    wide.push(0);
    let mut count = 0;
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() {
        return Err(OwnerError::Native);
    }
    let memory = LocalArgv(raw);
    if !(1..=8).contains(&count) {
        return Err(OwnerError::Conflict);
    }
    let mut result = vec![];
    for arg in unsafe { std::slice::from_raw_parts(memory.0, count as usize) } {
        if arg.is_null() {
            return Err(OwnerError::Conflict);
        }
        let mut length = 0;
        while length <= 32767 && unsafe { *arg.add(length) } != 0 {
            length += 1;
        }
        if length > 32767 {
            return Err(OwnerError::Conflict);
        }
        result.push(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(*arg, length)
        }));
    }
    Ok(result)
}
