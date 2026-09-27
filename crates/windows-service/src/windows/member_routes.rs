//! IP Helper transport for the portable addressed route adapter. Unwired: no
//! interface discovery, policy planning, automatic mutation, or Drop cleanup.
//!
//! Native keys are prefix+interface+next-hop, not prefix+metric:
//! https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipforwardentry2
//! Allocation/padding contract:
//! https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2

use crate::member_routes::{conflict, validate_route, NativeProof, Row, RowIo, MAX_TABLE_ROWS};
use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2,
            InitializeIpForwardEntry, SetIpForwardEntry2, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
            MIB_IPFORWARD_TABLE2,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{
        NlroManual, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
        MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
    },
};

/// Use only inside MemberRoutes with the owning member's live IdentityCheck.
/// The caller holds the privileged mutation lock across read/CAS/readback.
pub struct NativeRowIo;

impl RowIo for NativeRowIo {
    fn read(&mut self, destination: IpNet, index: u32) -> io::Result<Vec<Row>> {
        if index == 0 || destination != destination.trunc() {
            return Err(conflict());
        }
        let mut raw = ptr::null_mut();
        let family = if destination.addr().is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        let code = unsafe { GetIpForwardTable2(family, &mut raw) };
        let memory = TableMemory(raw);
        if code == ERROR_NOT_FOUND {
            return Ok(Vec::new());
        }
        status(code)?;
        if memory.0.is_null() {
            return Err(conflict());
        }
        // Access the flexible array through raw pointers: a zero-entry allocation
        // need not contain even one complete MIB_IPFORWARD_ROW2.
        let count = unsafe { ptr::addr_of!((*memory.0).NumEntries).read() } as usize;
        if count > MAX_TABLE_ROWS {
            return Err(conflict());
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        // Typed field address and row stride honor the SDK's alignment/padding.
        let first = unsafe { ptr::addr_of!((*memory.0).Table).cast::<MIB_IPFORWARD_ROW2>() };
        let rows = unsafe { std::slice::from_raw_parts(first, count) };
        let mut result = Vec::new();
        for raw in rows {
            if raw.InterfaceIndex != index {
                continue;
            }
            let prefix = decode_prefix(raw)?;
            if prefix.addr().is_ipv4() != destination.addr().is_ipv4() {
                return Err(conflict());
            }
            if prefix != destination {
                continue;
            }
            result.push(decode_row(raw, prefix)?);
            // No need to decode/enumerate further: more than one addressed row
            // is already an ownership conflict, even with identical next hops.
            if result.len() > 1 {
                return Err(conflict());
            }
        }
        Ok(result)
    }
    fn create(&mut self, row: &Row) -> io::Result<()> {
        let row = encode_row(row)?;
        status(unsafe { CreateIpForwardEntry2(&row) })
    }
    fn delete(&mut self, row: &Row) -> io::Result<()> {
        let row = encode_row(row)?;
        // Missing is a race/lost-ACK error, not unconditional success.
        status(unsafe { DeleteIpForwardEntry2(&row) })
    }
    fn set(&mut self, row: &Row) -> io::Result<()> {
        let row = encode_row(row)?;
        status(unsafe { SetIpForwardEntry2(&row) })
    }
}

struct TableMemory(*mut MIB_IPFORWARD_TABLE2);
impl Drop for TableMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}
fn status(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

pub(crate) fn decode_prefix(raw: &MIB_IPFORWARD_ROW2) -> io::Result<IpNet> {
    let address = decode_address(&raw.DestinationPrefix.Prefix, raw.InterfaceIndex)?;
    let prefix = IpNet::new(address, raw.DestinationPrefix.PrefixLength).map_err(|_| conflict())?;
    if prefix != prefix.trunc() {
        return Err(conflict());
    }
    Ok(prefix)
}
pub(crate) fn decode_row(raw: &MIB_IPFORWARD_ROW2, destination: IpNet) -> io::Result<Row> {
    let next = decode_address(&raw.NextHop, raw.InterfaceIndex)?;
    if next.is_ipv4() != destination.addr().is_ipv4() {
        return Err(conflict());
    }
    Ok(Row {
        route: RouteValue {
            destination,
            scope: RouteScope::WindowsInterface(raw.InterfaceIndex),
            interface: raw.InterfaceIndex,
            gateway: (!next.is_unspecified()).then_some(next),
            metric: raw.Metric,
        },
        luid: unsafe { raw.InterfaceLuid.Value },
        protocol: raw.Protocol,
        origin: raw.Origin,
        site_prefix_length: raw.SitePrefixLength,
        valid_lifetime: raw.ValidLifetime,
        preferred_lifetime: raw.PreferredLifetime,
        flags: [
            raw.Loopback as u8,
            raw.AutoconfigureAddress as u8,
            raw.Publish as u8,
            raw.Immortal as u8,
        ],
        // Age is intentionally excluded: it changes as an owned row ages.
    })
}
fn encode_row(row: &Row) -> io::Result<MIB_IPFORWARD_ROW2> {
    let r = &row.route;
    validate_route(r, r.destination, r.interface)?;
    if row.luid == 0
        || row
            != &Row::static_route(
                r.clone(),
                NativeProof {
                    index: r.interface,
                    luid: row.luid,
                },
            )
    {
        return Err(conflict());
    }
    let mut raw = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut raw) };
    raw.InterfaceIndex = r.interface;
    raw.InterfaceLuid = NET_LUID_LH { Value: row.luid };
    raw.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: encode_address(r.destination.addr(), r.interface),
        PrefixLength: r.destination.prefix_len(),
    };
    let unspecified = if r.destination.addr().is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    raw.NextHop = encode_address(r.gateway.unwrap_or(unspecified), r.interface);
    raw.Metric = r.metric;
    raw.Protocol = MIB_IPPROTO_NETMGMT;
    // Do not inherit InitializeIpForwardEntry's flag/sentinel defaults.
    raw.SitePrefixLength = 0;
    raw.ValidLifetime = u32::MAX;
    raw.PreferredLifetime = u32::MAX;
    raw.Loopback = false;
    raw.AutoconfigureAddress = false;
    raw.Publish = false;
    raw.Immortal = false;
    raw.Origin = NlroManual; // readback enforced; Origin/Age are stack-owned.
    Ok(raw)
}

fn encode_address(address: IpAddr, index: u32) -> SOCKADDR_INET {
    match address {
        IpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                ..Default::default()
            },
        },
        IpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: if ip.is_unicast_link_local() { index } else { 0 },
                },
                ..Default::default()
            },
        },
    }
}
fn decode_address(raw: &SOCKADDR_INET, index: u32) -> io::Result<IpAddr> {
    match unsafe { raw.si_family } {
        AF_INET => {
            let r = unsafe { raw.Ipv4 };
            if r.sin_port != 0 || r.sin_zero != [0; 8] {
                return Err(conflict());
            }
            Ok(IpAddr::V4(Ipv4Addr::from(
                unsafe { r.sin_addr.S_un.S_addr }.to_ne_bytes(),
            )))
        }
        AF_INET6 => {
            let r = unsafe { raw.Ipv6 };
            let scope = unsafe { r.Anonymous.sin6_scope_id };
            let ip = Ipv6Addr::from(unsafe { r.sin6_addr.u.Byte });
            // Zone zero is implicit in InterfaceIndex; a nonzero zone must
            // identify that same interface and only a link-local address.
            if r.sin6_port != 0
                || r.sin6_flowinfo != 0
                || (scope != 0 && (scope != index || !ip.is_unicast_link_local()))
            {
                return Err(conflict());
            }
            Ok(IpAddr::V6(ip))
        }
        _ => Err(conflict()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Pure conversion tests only. No IP Helper entry points (even Initialize)
    // are called; these compile in the Windows cross-check, never run on host.
    #[test]
    fn address_roundtrips_and_rejects_foreign_zone_and_family() {
        for ip in ["10.1.2.3", "2001:db8::1", "fe80::1", "0.0.0.0", "::"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(decode_address(&encode_address(ip, 7), 7).unwrap(), ip);
        }
        let mut raw = encode_address("fe80::1".parse().unwrap(), 8);
        assert!(decode_address(&raw, 7).is_err());
        raw.si_family = 999;
        assert!(decode_address(&raw, 7).is_err());
    }
    #[test]
    fn family_mismatch_and_noncanonical_prefix_fail() {
        let mut raw = MIB_IPFORWARD_ROW2 {
            InterfaceIndex: 7,
            DestinationPrefix: IP_ADDRESS_PREFIX {
                Prefix: encode_address("10.0.0.0".parse().unwrap(), 7),
                PrefixLength: 8,
            },
            NextHop: encode_address("::".parse().unwrap(), 7),
            ..Default::default()
        };
        assert!(decode_row(&raw, decode_prefix(&raw).unwrap()).is_err());
        raw.DestinationPrefix.Prefix = encode_address("10.1.1.1".parse().unwrap(), 7);
        assert!(decode_prefix(&raw).is_err());
        raw.DestinationPrefix.PrefixLength = 99;
        assert!(decode_prefix(&raw).is_err());
    }
}
