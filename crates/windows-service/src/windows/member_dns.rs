//! Owned IPv4 interface DNS and a separate dynamic ALE DNS-only policy.
//! Physical DNS settings stay unchanged; no registry, PowerShell or WMI writes.
//!
//! Get uses Version1/Flags0. Set uses ONLY DNS_SETTING_NAMESERVER; IPv6 DNS-server
//! configuration is deliberately unimplemented (IPv6 data traffic is unrelated).
//! Only fields returned by Version1 can be observed. Unknown returned flags and
//! profile DNS are rejected by the portable adapter; no hidden-policy guarantee.
//! The owner must supply authoritative ownership, journal before apply and fence
//! interface lifecycle. Native mapping checks alone do NOT prove ownership.
//!
//! https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getinterfacednssettings
//! https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings
//! https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freeinterfacednssettings

use crate::member_dns::{
    decode_wide, DnsError, DnsIo, Identity, OwnedDns, OwnedInterface, Result, Settings,
    MAX_STRING_UNITS,
};
use std::ptr;
use windows_sys::{
    core::GUID,
    Win32::NetworkManagement::{
        IpHelper::{
            ConvertInterfaceGuidToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
            ConvertInterfaceLuidToIndex, FreeInterfaceDnsSettings, GetInterfaceDnsSettings,
            SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
            DNS_SETTING_NAMESERVER,
        },
        Ndis::NET_LUID_LH,
    },
};

/// No native calls in construction. Ownership is re-attested at each operation.
pub(crate) fn owned<I: Identity>(
    interface: OwnedInterface,
    identity: I,
) -> Result<OwnedDns<I, NativeDnsIo>> {
    OwnedDns::new(interface, identity, NativeDnsIo { _private: () })
}

pub(crate) struct NativeDnsIo {
    _private: (),
}

impl DnsIo for NativeDnsIo {
    fn verify_mapping(&mut self, interface: &OwnedInterface) -> Result<()> {
        let expected_guid = guid(interface);
        let expected_luid = NET_LUID_LH {
            Value: interface.luid,
        };
        let mut from_guid = NET_LUID_LH::default();
        let mut from_index = NET_LUID_LH::default();
        let mut actual_index = 0;
        let mut actual_guid = GUID::from_u128(0);
        // All pointers refer to initialized, correctly aligned local objects.
        status(unsafe { ConvertInterfaceGuidToLuid(&expected_guid, &mut from_guid) })?;
        status(unsafe { ConvertInterfaceLuidToIndex(&expected_luid, &mut actual_index) })?;
        status(unsafe { ConvertInterfaceIndexToLuid(interface.index, &mut from_index) })?;
        status(unsafe { ConvertInterfaceLuidToGuid(&expected_luid, &mut actual_guid) })?;
        // Value is the initialized integral union representation of NET_LUID_LH.
        if unsafe { from_guid.Value } != interface.luid
            || unsafe { from_index.Value } != interface.luid
            || actual_index != interface.index
            || actual_guid.data1 != expected_guid.data1
            || actual_guid.data2 != expected_guid.data2
            || actual_guid.data3 != expected_guid.data3
            || actual_guid.data4 != expected_guid.data4
        {
            return Err(DnsError::Ownership);
        }
        Ok(())
    }

    fn read(&mut self, interface: &OwnedInterface) -> Result<Settings> {
        let mut raw = read_request();
        // Only Version is populated. In particular do NOT pass an IPv6 flag.
        status(unsafe { GetInterfaceDnsSettings(guid(interface), &mut raw) })?;
        // The API transfers the successful result's allocations to this guard.
        // Every decode/validation exit below still frees them exactly once.
        let memory = DnsMemory(raw);
        let raw = &memory.0;
        // Successful Get supplies valid, NUL-terminated UTF-16 string pointers
        // (or NULL), kept live by memory throughout these bounded copies.
        unsafe {
            Ok(Settings {
                version: raw.Version,
                flags: raw.Flags,
                domain: copy_string(raw.Domain)?,
                name_server: copy_string(raw.NameServer)?,
                search_list: copy_string(raw.SearchList)?,
                registration_enabled: raw.RegistrationEnabled,
                register_adapter_name: raw.RegisterAdapterName,
                enable_llmnr: raw.EnableLLMNR,
                query_adapter_name: raw.QueryAdapterName,
                profile_name_server: copy_string(raw.ProfileNameServer)?,
            })
        }
    }

    fn write_nameserver(&mut self, interface: &OwnedInterface, value: Option<&str>) -> Result<()> {
        // The portable adapter has already validated the entire desired snapshot
        // and ownership. No retrieved flags/other pointers are copied into Set.
        let mut encoded = match value {
            Some(text) => {
                if text.contains('\0') || text.encode_utf16().count() > MAX_STRING_UNITS {
                    return Err(DnsError::Unsupported);
                }
                Some(text.encode_utf16().chain(Some(0)).collect::<Vec<_>>())
            }
            None => None,
        };
        let pointer = encoded.as_mut().map_or(ptr::null_mut(), |v| v.as_mut_ptr());
        let raw = write_request(pointer);
        // Set borrows the input string only for this call. NULL and empty remain
        // distinct journal states; exact readback, not assumed reset semantics,
        // decides whether restoring an empty owned baseline actually succeeded.
        status(unsafe { SetInterfaceDnsSettings(guid(interface), &raw) })
    }
}

fn read_request() -> DNS_INTERFACE_SETTINGS {
    DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        ..Default::default()
    }
}

fn write_request(name_server: *mut u16) -> DNS_INTERFACE_SETTINGS {
    DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        NameServer: name_server,
        ..Default::default()
    }
}

struct DnsMemory(DNS_INTERFACE_SETTINGS);
impl Drop for DnsMemory {
    fn drop(&mut self) {
        // Exactly the settings returned by a successful Get, never the input to
        // Set (whose buffer is Rust-owned). No logging of any settings contents.
        unsafe { FreeInterfaceDnsSettings(&mut self.0) };
    }
}

/// Caller guarantees a readable API-owned NUL-terminated string or NULL.
unsafe fn copy_string(pointer: *const u16) -> Result<Option<String>> {
    if pointer.is_null() {
        return Ok(None);
    }
    decode_wide(|offset| unsafe { *pointer.add(offset) }).map(Some)
}

fn guid(interface: &OwnedInterface) -> GUID {
    GUID::from_u128(u128::from_be_bytes(interface.guid))
}

fn status(code: u32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(DnsError::Native(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure construction/copy tests only: no Get/Set/conversion/Free calls.
    #[test]
    fn requests_never_select_ipv6_or_populate_unrelated_fields() {
        let read = read_request();
        assert_eq!(read.Version, 1);
        assert_eq!(read.Flags, 0);
        assert!(read.NameServer.is_null());
        let mut text = [b'9' as u16, 0];
        let write = write_request(text.as_mut_ptr());
        assert_eq!(write.Version, 1);
        assert_eq!(write.Flags, 2);
        assert_eq!(write.NameServer, text.as_mut_ptr());
        assert!(write.Domain.is_null());
        assert!(write.SearchList.is_null());
        assert!(write.ProfileNameServer.is_null());
        assert_eq!(write.RegistrationEnabled, 0);
        assert_eq!(write.RegisterAdapterName, 0);
        assert_eq!(write.EnableLLMNR, 0);
        assert_eq!(write.QueryAdapterName, 0);
    }

    #[test]
    fn copies_null_empty_and_unicode_without_owning_the_source() {
        assert_eq!(unsafe { copy_string(ptr::null()) }.unwrap(), None);
        assert_eq!(
            unsafe { copy_string([0].as_ptr()) }.unwrap(),
            Some(String::new())
        );
        let text: Vec<u16> = "пример.invalid".encode_utf16().chain(Some(0)).collect();
        assert_eq!(
            unsafe { copy_string(text.as_ptr()) }.unwrap().as_deref(),
            Some("пример.invalid")
        );
        assert_eq!(
            unsafe { copy_string([0xd800, 0].as_ptr()) },
            Err(DnsError::Unsupported)
        );
    }
}

// DNS-only ALE policy has its own original dynamic BFE engine. The existing
// static index/TUN guard and its SessionKind/lifetime remain independent.
use super::member_carrier_guard::{
    arbitration_for_engine, decode_dns_filter, decode_sublayer, guid as wfp_guid,
    validate_arbitration_keys, EncodedFilter, NAME,
};
use crate::{
    member_carrier_guard::{Key, Snapshot as GuardSnapshot},
    member_dns::DnsPolicy,
};
use nelomai_client_tunnel::redundancy::SessionScope;
use std::{collections::BTreeMap, io, net::IpAddr, os::windows::ffi::OsStrExt, path::Path};
use windows_sys::Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*};

pub(crate) struct DnsPolicyOwner {
    scope: SessionScope,
    original: Option<HANDLE>,
    app_id: Vec<u8>,
    current: Option<DnsPolicy>,
    ids: BTreeMap<Key, u64>,
    failed: bool,
}
fn dns_status(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
fn dns_checked<T>(
    value: impl Into<std::result::Result<T, crate::member_carrier_guard::GuardError>>,
) -> io::Result<T> {
    value
        .into()
        .map_err(|_| io::Error::other("worker_dns_policy_conflict"))
}
struct BfeMemory<T>(*mut T);
impl<T> Drop for BfeMemory<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as _) }
        }
    }
}
struct DnsTransaction(HANDLE, bool);
impl Drop for DnsTransaction {
    fn drop(&mut self) {
        if !self.1 {
            unsafe { FwpmTransactionAbort0(self.0) };
        }
    }
}
impl DnsPolicyOwner {
    /// No filters in construction. Caller retains this owner before replace.
    /// The path must come from the original verified pinned worker image.
    pub(crate) fn open(scope: SessionScope, worker_image: &Path) -> io::Result<Self> {
        let path = worker_image
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut app = ptr::null_mut();
        dns_status(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app) })?;
        let memory = BfeMemory(app);
        let blob =
            unsafe { memory.0.as_ref() }.ok_or_else(|| io::Error::other("worker_dns_app_id"))?;
        if blob.size == 0 || blob.size > 65536 || blob.data.is_null() {
            return Err(io::Error::other("worker_dns_app_id"));
        }
        let app_id = unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut handle = ptr::null_mut();
        dns_status(unsafe {
            FwpmEngineOpen0(ptr::null(), 10, ptr::null(), &session, &mut handle)
        })?;
        if handle.is_null() {
            return Err(io::Error::other("worker_dns_engine"));
        }
        Ok(Self {
            scope,
            original: Some(handle),
            app_id,
            current: None,
            ids: BTreeMap::new(),
            failed: false,
        })
    }
    fn handle(&self) -> io::Result<HANDLE> {
        self.original
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
    fn read_policy(&self, policy: &DnsPolicy) -> io::Result<()> {
        let handle = self.handle()?;
        let mut sub = ptr::null_mut();
        dns_status(unsafe {
            FwpmSubLayerGetByKey0(handle, &wfp_guid(policy.sublayer.key), &mut sub)
        })?;
        let memory = BfeMemory(sub);
        let raw =
            unsafe { memory.0.as_ref() }.ok_or_else(|| io::Error::other("worker_dns_sublayer"))?;
        if dns_checked(unsafe { decode_sublayer(raw, policy.sublayer.key) })? != policy.sublayer {
            return Err(io::Error::other("worker_dns_sublayer"));
        }
        for filter in &policy.filters {
            let mut raw = ptr::null_mut();
            dns_status(unsafe {
                FwpmFilterGetByKey0(handle, &wfp_guid(filter.policy.key), &mut raw)
            })?;
            let memory = BfeMemory(raw);
            let raw = unsafe { memory.0.as_ref() }
                .ok_or_else(|| io::Error::other("worker_dns_filter"))?;
            let actual = dns_checked(unsafe { decode_dns_filter(raw, filter) })?;
            if self.ids.get(&filter.policy.key) != Some(&actual.id) {
                return Err(io::Error::other("worker_dns_filter_id"));
            }
        }
        let snapshot = GuardSnapshot {
            version: 2,
            scope: self.scope.clone(),
            carrier: None,
            egress: [None, None],
            sublayer: Some(policy.sublayer.clone()),
            filters: policy.filters.iter().map(|f| f.policy.clone()).collect(),
        };
        let keys = policy
            .filters
            .iter()
            .map(|f| f.policy.key)
            .collect::<Vec<_>>();
        let inventory = dns_checked(arbitration_for_engine(handle))?;
        dns_checked(validate_arbitration_keys(
            &self.scope,
            &snapshot,
            &self.ids,
            &inventory,
            &[],
            policy.sublayer.key,
            &keys,
        ))
    }
    pub(crate) fn replace(
        &mut self,
        tun_luid: u64,
        bypasses: &[ipnet::Ipv4Net],
        endpoints: &[(IpAddr, u64)],
    ) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("worker_dns_cleanup_pending"));
        }
        let desired = crate::member_dns::dns_policy(
            &self.scope,
            tun_luid,
            bypasses,
            endpoints,
            &self.app_id,
        )?;
        let handle = self.handle()?;
        self.failed = true; // retain original even if any native ACK is lost
        dns_status(unsafe { FwpmTransactionBegin0(handle, 0) })?;
        let mut tx = DnsTransaction(handle, false);
        if let Some(current) = &self.current {
            self.read_policy(current)?;
            for filter in &current.filters {
                dns_status(unsafe {
                    FwpmFilterDeleteByKey0(handle, &wfp_guid(filter.policy.key))
                })?;
            }
        } else {
            let mut name = NAME.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let sub = FWPM_SUBLAYER0 {
                subLayerKey: wfp_guid(desired.sublayer.key),
                weight: desired.sublayer.weight,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: ptr::null_mut(),
                },
                ..Default::default()
            };
            dns_status(unsafe { FwpmSubLayerAdd0(handle, &sub, ptr::null_mut()) })?;
        }
        self.ids.clear();
        for filter in &desired.filters {
            let encoded = dns_checked(EncodedFilter::dns(filter))?;
            let mut id = 0;
            dns_status(unsafe { FwpmFilterAdd0(handle, &encoded.raw, ptr::null_mut(), &mut id) })?;
            if id == 0 {
                return Err(io::Error::other("worker_dns_filter_id"));
            }
            self.ids.insert(filter.policy.key, id);
        }
        self.read_policy(&desired)?;
        dns_status(unsafe { FwpmTransactionCommit0(handle) })?;
        tx.1 = true;
        self.current = Some(desired);
        #[cfg(test)]
        if super::member_worker_factory_native_tests::STOP_FAULT.with(|fault| {
            if fault.get()
                == Some(super::member_worker_factory_native_tests::StopFault::DnsCommitAck)
            {
                fault.set(None);
                true
            } else {
                false
            }
        }) {
            return Err(io::Error::other("worker_dns_commit_ack_lost"));
        }
        self.failed = false;
        self.verify()
    }
    pub(crate) fn verify(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("worker_dns_cleanup_pending"));
        }
        self.failed = true;
        let handle = self.handle()?;
        dns_status(unsafe { FwpmTransactionBegin0(handle, FWPM_TXN_READ_ONLY) })?;
        let mut tx = DnsTransaction(handle, false);
        self.read_policy(
            self.current
                .as_ref()
                .ok_or_else(|| io::Error::other("worker_dns_not_installed"))?,
        )?;
        dns_status(unsafe { FwpmTransactionCommit0(handle) })?;
        tx.1 = true;
        self.failed = false;
        Ok(())
    }
    pub(crate) fn close(&mut self) -> io::Result<()> {
        if let Some(handle) = self.original {
            dns_status(unsafe { FwpmEngineClose0(handle) })?;
            self.original = None;
        }
        Ok(())
    }
}
impl Drop for DnsPolicyOwner {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
