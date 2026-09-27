//! Owned IPv4 interface DNS. No global DNS, registry, PowerShell or WMI access.
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
