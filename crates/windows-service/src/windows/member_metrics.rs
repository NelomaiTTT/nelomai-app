//! Read-only, addressed native telemetry for a member created by the engine.
//! Not a recovery/adoption API; the session owner supplies the PID and interface
//! index obtained from its own Start. This is not yet connected to pair IPC.

use super::wide;
use crate::member_metrics::{
    decode_awg_uapi, decode_wireguard_nt, query_awg_uapi, query_wireguard_nt, SecretNtConfiguration,
};
use crate::redundancy::slot_service_name;
use nelomai_client_tunnel::{TunnelMetrics, TunnelTransport};
use nelomai_contracts::dispatcher::TunnelSlot;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    FreeLibrary, GetLastError, ERROR_MORE_DATA, FILETIME, HANDLE, HMODULE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
use windows_sys::Win32::NetworkManagement::Ndis::{NET_IF_OPER_STATUS_UP, NET_LUID_LH};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn rejected() -> io::Error {
    io::Error::other("member_metrics_identity_unconfirmed")
}

fn member_name(slot: TunnelSlot, transport: TunnelTransport) -> &'static str {
    match transport {
        TunnelTransport::WireGuard => match slot {
            TunnelSlot::A => "nelomai-a",
            TunnelSlot::B => "nelomai-b",
        },
        TunnelTransport::AmneziaWg3 => slot_service_name(slot, transport),
    }
}

fn service_pid(slot: TunnelSlot, transport: TunnelTransport) -> io::Result<u32> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| rejected())?;
    let service = manager
        .open_service(
            slot_service_name(slot, transport),
            ServiceAccess::QUERY_STATUS,
        )
        .map_err(|_| rejected())?;
    let status = service.query_status().map_err(|_| rejected())?;
    if status.current_state != ServiceState::Running {
        return Err(rejected());
    }
    status
        .process_id
        .filter(|pid| *pid != 0)
        .ok_or_else(rejected)
}

fn process_stamp(pid: u32) -> io::Result<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(rejected());
    }
    let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    let mut exit = 0;
    if unsafe {
        GetProcessTimes(
            owned.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
        || unsafe { GetExitCodeProcess(owned.as_raw_handle(), &mut exit) } == 0
        || exit != 259
    {
        return Err(rejected());
    }
    Ok(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
}

fn interface(index: u32, name: &str) -> io::Result<MIB_IF_ROW2> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    if index == 0
        || unsafe { GetIfEntry2(&mut row) } != NO_ERROR
        || row.OperStatus != NET_IF_OPER_STATUS_UP
    {
        return Err(rejected());
    }
    let end = row
        .Alias
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(rejected)?;
    if !String::from_utf16(&row.Alias[..end])
        .map_err(|_| rejected())?
        .eq_ignore_ascii_case(name)
    {
        return Err(rejected());
    }
    Ok(row)
}

/// Transport bytes include keepalives. Interface bytes are reported separately
/// for the health driver's data-progress observation; neither replaces DNS probes.
pub struct MemberObservation {
    pub transport: TunnelMetrics,
    pub interface_received_bytes: u64,
    pub interface_sent_bytes: u64,
    pub received_unicast_packets: u64,
    pub sent_unicast_packets: u64,
}

pub struct MemberMetrics {
    slot: TunnelSlot,
    transport: TunnelTransport,
    pid: u32,
    created: u64,
    index: u32,
    luid: u64,
    guid: [u8; 16],
    peer: [u8; 32],
    started: u64,
}

impl MemberMetrics {
    /// Called only after this session's addressed Start, never to adopt a
    /// service found merely by its name. No arbitrary name, path or DLL input.
    pub fn capture(
        slot: TunnelSlot,
        transport: TunnelTransport,
        pid: u32,
        index: u32,
        peer: [u8; 32],
        started: u64,
    ) -> io::Result<Self> {
        if pid == 0 || service_pid(slot, transport)? != pid || started > epoch_millis()? {
            return Err(rejected());
        }
        let created = process_stamp(pid)?;
        let row = interface(index, member_name(slot, transport))?;
        let result = Self {
            slot,
            transport,
            pid,
            created,
            index,
            luid: unsafe { row.InterfaceLuid.Value },
            guid: guid_bytes(&row),
            peer,
            started,
        };
        result.verify()?;
        Ok(result)
    }

    pub(crate) fn capture_owned(
        slot: TunnelSlot,
        transport: TunnelTransport,
        proof: crate::member_owner::NativeProof,
        peer: [u8; 32],
        started: u64,
    ) -> io::Result<Self> {
        let value = Self::capture(
            slot,
            transport,
            proof.process.pid,
            proof.interface.index,
            peer,
            started,
        )?;
        owned_packet_counts(&value.verify()?, value.pid, value.created, &proof)?;
        Ok(value)
    }

    fn verify(&self) -> io::Result<MIB_IF_ROW2> {
        if service_pid(self.slot, self.transport)? != self.pid
            || process_stamp(self.pid)? != self.created
        {
            return Err(rejected());
        }
        let row = interface(self.index, member_name(self.slot, self.transport))?;
        if unsafe { row.InterfaceLuid.Value } != self.luid || guid_bytes(&row) != self.guid {
            return Err(rejected());
        }
        Ok(row)
    }

    pub async fn read(&self) -> io::Result<MemberObservation> {
        self.verify()?;
        let name = member_name(self.slot, self.transport);
        let transport = match self.transport {
            TunnelTransport::WireGuard => {
                let driver = NtAdapter::open(name, self.luid)?;
                let data = driver.configuration()?;
                decode_wireguard_nt(data.bytes(), &self.peer, self.started, epoch_millis()?)?
            }
            TunnelTransport::AmneziaWg3 => {
                let path = format!(r"\\.\pipe\ProtectedPrefix\Administrators\AmneziaWG\{name}");
                let mut pipe = tokio::net::windows::named_pipe::ClientOptions::new()
                    .open(path)
                    .map_err(|_| rejected())?;
                let mut server = 0;
                if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server) } == 0
                    || server != self.pid
                {
                    return Err(rejected());
                }
                self.verify()?;
                let bytes = query_awg_uapi(&mut pipe, Duration::from_secs(1)).await?;
                decode_awg_uapi(&bytes, &self.peer, self.started, epoch_millis()?)?
            }
        };
        let row = self.verify()?;
        Ok(MemberObservation {
            transport,
            interface_received_bytes: row.InOctets,
            interface_sent_bytes: row.OutOctets,
            received_unicast_packets: row.InUcastPkts,
            sent_unicast_packets: row.OutUcastPkts,
        })
    }
}

fn guid_bytes(row: &MIB_IF_ROW2) -> [u8; 16] {
    let g = row.InterfaceGuid;
    let mut bytes = [0; 16];
    bytes[..4].copy_from_slice(&g.data1.to_be_bytes());
    bytes[4..6].copy_from_slice(&g.data2.to_be_bytes());
    bytes[6..8].copy_from_slice(&g.data3.to_be_bytes());
    bytes[8..].copy_from_slice(&g.data4);
    bytes
}
fn owned_packet_counts(
    row: &MIB_IF_ROW2,
    pid: u32,
    created: u64,
    p: &crate::member_owner::NativeProof,
) -> io::Result<(u64, u64)> {
    if pid != p.process.pid
        || created != p.process.creation_time
        || row.InterfaceIndex != p.interface.index
        || unsafe { row.InterfaceLuid.Value } != p.interface.luid
        || guid_bytes(row) != p.interface.guid
    {
        return Err(rejected());
    }
    Ok((row.OutUcastPkts, row.InUcastPkts))
}

fn epoch_millis() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| rejected())?
        .as_millis()
        .try_into()
        .map_err(|_| rejected())
}

type OpenAdapter = unsafe extern "system" fn(*const u16) -> HANDLE;
type CloseAdapter = unsafe extern "system" fn(HANDLE);
type AdapterLuid = unsafe extern "system" fn(HANDLE, *mut NET_LUID_LH);
type AdapterState = unsafe extern "system" fn(HANDLE, *mut u32) -> i32;
type Configuration = unsafe extern "system" fn(HANDLE, *mut std::ffi::c_void, *mut u32) -> i32;

struct Library(HMODULE);
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

struct NtAdapter {
    _library: Library,
    adapter: HANDLE,
    close: CloseAdapter,
    configuration: Configuration,
}
impl Drop for NtAdapter {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.adapter);
        }
    }
}

impl NtAdapter {
    fn open(name: &str, expected_luid: u64) -> io::Result<Self> {
        let path = std::env::current_exe()?.with_file_name("wireguard.dll");
        let library = unsafe {
            LoadLibraryExW(
                wide(path).as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if library.is_null() {
            return Err(rejected());
        }
        let library = Library(library);
        // Export names and signatures are the pinned WireGuardNT1.1 ABI. The
        // library outlives the adapter and all function pointers.
        let (open, close, luid, state, configuration): (
            OpenAdapter,
            CloseAdapter,
            AdapterLuid,
            AdapterState,
            Configuration,
        ) = unsafe {
            (
                std::mem::transmute::<unsafe extern "system" fn() -> isize, OpenAdapter>(
                    GetProcAddress(library.0, c"WireGuardOpenAdapter".as_ptr().cast())
                        .ok_or_else(rejected)?,
                ),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, CloseAdapter>(
                    GetProcAddress(library.0, c"WireGuardCloseAdapter".as_ptr().cast())
                        .ok_or_else(rejected)?,
                ),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, AdapterLuid>(
                    GetProcAddress(library.0, c"WireGuardGetAdapterLUID".as_ptr().cast())
                        .ok_or_else(rejected)?,
                ),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, AdapterState>(
                    GetProcAddress(library.0, c"WireGuardGetAdapterState".as_ptr().cast())
                        .ok_or_else(rejected)?,
                ),
                std::mem::transmute::<unsafe extern "system" fn() -> isize, Configuration>(
                    GetProcAddress(library.0, c"WireGuardGetConfiguration".as_ptr().cast())
                        .ok_or_else(rejected)?,
                ),
            )
        };
        let adapter = unsafe { open(wide(name).as_ptr()) };
        if adapter.is_null() {
            return Err(rejected());
        }
        let result = Self {
            _library: library,
            adapter,
            close,
            configuration,
        };
        let mut actual = NET_LUID_LH::default();
        let mut up = 0;
        unsafe {
            luid(adapter, &mut actual);
        }
        if unsafe { actual.Value } != expected_luid
            || unsafe { state(adapter, &mut up) } == 0
            || up != 1
        {
            return Err(rejected());
        }
        Ok(result)
    }

    fn configuration(&self) -> io::Result<SecretNtConfiguration> {
        query_wireguard_nt(|words, length| {
            let buffer = if words.is_empty() {
                std::ptr::null_mut()
            } else {
                words.as_mut_ptr().cast()
            };
            if unsafe { (self.configuration)(self.adapter, buffer, length) } != 0 {
                Ok(true)
            } else if unsafe { GetLastError() } == ERROR_MORE_DATA {
                Ok(false)
            } else {
                Err(rejected())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sample_counts_only_unicast_packets_and_checks_full_retained_identity() {
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: 7,
            ..Default::default()
        };
        row.InterfaceLuid.Value = 9;
        row.InterfaceGuid = windows_sys::core::GUID::from_u128(0x11111111222233334444555555555555);
        row.InUcastPkts = 11;
        row.OutUcastPkts = 13;
        row.InOctets = 999;
        row.OutOctets = 888;
        row.InNUcastPkts = 55;
        row.OutNUcastPkts = 66;
        let p = crate::member_owner::NativeProof {
            process: crate::member_owner::ProcessProof {
                pid: 3,
                creation_time: 5,
            },
            interface: crate::member_owner::InterfaceProof {
                index: 7,
                luid: 9,
                guid: 0x11111111222233334444555555555555u128.to_be_bytes(),
            },
        };
        assert_eq!(owned_packet_counts(&row, 3, 5, &p).unwrap(), (13, 11));
        assert!(owned_packet_counts(&row, 3, 6, &p).is_err());
        row.InterfaceGuid = windows_sys::core::GUID::from_u128(0);
        assert!(owned_packet_counts(&row, 3, 5, &p).is_err());
    }
    fn send<T: Send>(_: T) {}
    // The helper's Tokio owner needs an independently cancellable task. A native
    // HANDLE/library guard must never be retained across a pipe await.
    fn metrics_future_is_send(member: &MemberMetrics) {
        send(member.read());
    }
    #[test]
    fn read_future_can_be_owned_by_health_task() {
        let _check: fn(&MemberMetrics) = metrics_future_is_send;
    }
}
