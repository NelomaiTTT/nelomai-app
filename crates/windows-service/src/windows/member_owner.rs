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

use super::install::{engine_primitive, open_slot_service, slot_config_path};
use crate::member_owner::{
    Intent, InterfaceProof, MemberIo, NativeProof, Observation, OwnerError, ProcessProof, Record,
    Result, ServiceObservation,
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
use windows_service::service::{ServiceAccess, ServiceStartType, ServiceState, ServiceType};
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_INVALID_PARAMETER, FILETIME},
    NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
    System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    },
    UI::Shell::CommandLineToArgvW,
};

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
    fn inspect(&mut self, intent: &Intent, retained: Option<&NativeProof>) -> Result<Observation> {
        let before = self.inspect_once(intent, retained)?;
        if self.inspect_once(intent, retained)? != before {
            return Err(OwnerError::Conflict);
        }
        Ok(before)
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
        let action = match self.transport {
            TunnelTransport::WireGuard => EnginePrimitive::StartWireguardSlot { slot: self.slot },
            TunnelTransport::AmneziaWg3 => EnginePrimitive::StartAmneziawgSlot { slot: self.slot },
        };
        engine_primitive(action, &self.engine).map_err(|_| OwnerError::Native)
    }
    fn stop_slot(
        &mut self,
        intent: &Intent,
        retained: Option<&NativeProof>,
        expected: &Observation,
    ) -> Result<()> {
        self.require_same(intent, retained, expected)?;
        engine_primitive(EnginePrimitive::StopSlot { slot: self.slot }, &self.engine)
            .map_err(|_| OwnerError::Native)
    }
    fn rebind(
        &mut self,
        intent: &Intent,
        proof: &NativeProof,
        expected: &Observation,
    ) -> Result<()> {
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
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(OwnerError::Native)
        };
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
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
    if creation_time == 0 {
        return Err(OwnerError::Native);
    }
    Ok(Some((ProcessProof { pid, creation_time }, code)))
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
fn command_arguments(command: &std::ffi::OsStr) -> Result<Vec<OsString>> {
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
