//! Read-only IPHelper discovery used by the native pair factory.

use super::member_routes::{decode_prefix, decode_row};
use crate::{
    member_physical::{
        Family, InterfaceIdentity, InterfaceRecord, PhysicalProof, PhysicalRoute, PhysicalSnapshot,
    },
    member_routes::{Row, MAX_TABLE_ROWS},
};
use std::{collections::BTreeMap, io, ptr};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_FOUND, NO_ERROR},
    NetworkManagement::{
        IpHelper::{
            FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, MIB_IF_ROW2,
            MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6},
};

/// The owned list comes from the member owner, not discovery/name adoption.
/// Reads both families even when the caller currently needs only an IPv4 host.
/// IPHelper has no atomic route+interface snapshot; races observed during this
/// capture fail closed. Callers still need fresh verification before mutation.
pub(crate) fn capture(owned: &[InterfaceIdentity]) -> io::Result<PhysicalSnapshot> {
    let rows = full_route_table()?;
    let mut keys = BTreeMap::new();
    for row in &rows {
        let key = (
            Family::of(row.route.destination.addr()),
            row.route.interface,
        );
        if row.route.interface == 0
            || row.luid == 0
            || keys
                .insert(key, row.luid)
                .is_some_and(|old| old != row.luid)
        {
            return Err(invalid());
        }
    }
    let mut interfaces = Vec::with_capacity(keys.len());
    for ((family, index), luid) in keys {
        interfaces.push(read_interface(family, index, luid)?);
    }
    PhysicalSnapshot::new(rows, interfaces, owned).map_err(io::Error::other)
}

/// Route tables only, from both families. No NIC inventory or path selection.
/// Keep duplicate/competing rows; table order is not an ownership fact.
pub(crate) fn full_route_table() -> io::Result<Vec<Row>> {
    let mut rows = read_family(Family::V4)?;
    rows.extend(read_family(Family::V6)?);
    rows.sort_by_key(|r| {
        (
            (r.route.destination, r.route.interface),
            r.route.gateway,
            r.route.metric,
            r.luid,
        )
    });
    Ok(rows)
}

/// Re-enumerates both families and interface evidence on EVERY invocation.
/// Exact Row metadata must survive; no equivalence/adoption by interface index,
/// alias, next-hop or metric, and no route/interface/DNS writes of any kind.
pub(crate) fn verify(expected: &PhysicalRoute, owned: &[InterfaceIdentity]) -> io::Result<()> {
    capture(owned)?.verify(expected).map_err(io::Error::other)
}

fn native_family(family: Family) -> ADDRESS_FAMILY {
    match family {
        Family::V4 => AF_INET,
        Family::V6 => AF_INET6,
    }
}
fn invalid() -> io::Error {
    io::Error::other("physical_discovery_invalid")
}
fn status(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
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
fn read_family(family: Family) -> io::Result<Vec<Row>> {
    let mut raw = ptr::null_mut();
    let code = unsafe { GetIpForwardTable2(native_family(family), &mut raw) };
    let memory = TableMemory(raw);
    if code == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    status(code)?;
    #[cfg(test)]
    super::member_carrier_factory_test_os::route_table_read()?;
    // Allocation belongs to IPHelper and remains live until decoding completes.
    unsafe { decode_table(memory.0, family) }
}

/// Safety: non-null `raw` must point to an SDK table allocation valid for its
/// declared count (or a test-owned equivalent). Use raw field addresses to honor
/// SDK padding and avoid constructing a one-row reference for an empty table.
unsafe fn decode_table(raw: *const MIB_IPFORWARD_TABLE2, family: Family) -> io::Result<Vec<Row>> {
    if raw.is_null() {
        return Err(invalid());
    }
    let count = unsafe { ptr::addr_of!((*raw).NumEntries).read() } as usize;
    if count > MAX_TABLE_ROWS {
        return Err(invalid());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let first = unsafe { ptr::addr_of!((*raw).Table).cast::<MIB_IPFORWARD_ROW2>() };
    let rows = unsafe { std::slice::from_raw_parts(first, count) };
    let mut result = Vec::with_capacity(count);
    for raw in rows {
        let prefix = decode_prefix(raw)?;
        if Family::of(prefix.addr()) != family {
            return Err(invalid());
        }
        result.push(decode_row(raw, prefix)?);
    }
    Ok(result)
}

fn read_interface(family: Family, index: u32, luid: u64) -> io::Result<InterfaceRecord> {
    // Query by index, then compare LUID and GUID: never silently follow a LUID
    // to a different index or reuse an index that now belongs to another NIC.
    let mut before = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut before) })?;
    let mut ip = MIB_IPINTERFACE_ROW {
        Family: native_family(family),
        InterfaceIndex: index,
        InterfaceLuid: NET_LUID_LH { Value: luid },
        ..Default::default()
    };
    status(unsafe { GetIpInterfaceEntry(&mut ip) })?;
    let record = decode_interface(&before, &ip, family, index, luid)?;
    let mut after = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut after) })?;
    if decode_interface(&after, &ip, family, index, luid)? != record {
        return Err(invalid());
    }
    Ok(record)
}

/// Identity-only cleanup proof: losing/changing a default gateway or interface
/// metric does not revoke authority over an exact journal-owned bypass row.
/// No route selection, physical classification or mutation is performed here.
pub(crate) fn read_identity(index: u32) -> io::Result<InterfaceIdentity> {
    if index == 0 {
        return Err(invalid());
    }
    let mut before = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut before) })?;
    let identity = decode_identity(&before)?;
    let mut after = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut after) })?;
    if identity.index != index || decode_identity(&after)? != identity {
        return Err(invalid());
    }
    Ok(identity)
}
fn decode_identity(row: &MIB_IF_ROW2) -> io::Result<InterfaceIdentity> {
    let mut guid = [0; 16];
    guid[..4].copy_from_slice(&row.InterfaceGuid.data1.to_be_bytes());
    guid[4..6].copy_from_slice(&row.InterfaceGuid.data2.to_be_bytes());
    guid[6..8].copy_from_slice(&row.InterfaceGuid.data3.to_be_bytes());
    guid[8..].copy_from_slice(&row.InterfaceGuid.data4);
    let identity = InterfaceIdentity {
        index: row.InterfaceIndex,
        luid: unsafe { row.InterfaceLuid.Value },
        guid,
    };
    if identity.index == 0 || identity.luid == 0 || identity.guid == [0; 16] {
        return Err(invalid());
    }
    Ok(identity)
}

fn decode_interface(
    row: &MIB_IF_ROW2,
    ip: &MIB_IPINTERFACE_ROW,
    family: Family,
    index: u32,
    luid: u64,
) -> io::Result<InterfaceRecord> {
    if index == 0
        || luid == 0
        || row.InterfaceIndex != index
        || ip.InterfaceIndex != index
        || unsafe { row.InterfaceLuid.Value } != luid
        || unsafe { ip.InterfaceLuid.Value } != luid
        || ip.Family != native_family(family)
    {
        return Err(invalid());
    }
    let end = row.Alias.iter().position(|c| *c == 0).ok_or_else(invalid)?;
    let alias = String::from_utf16(&row.Alias[..end]).map_err(|_| invalid())?;
    let mut guid = [0; 16];
    guid[..4].copy_from_slice(&row.InterfaceGuid.data1.to_be_bytes());
    guid[4..6].copy_from_slice(&row.InterfaceGuid.data2.to_be_bytes());
    guid[6..8].copy_from_slice(&row.InterfaceGuid.data3.to_be_bytes());
    guid[8..].copy_from_slice(&row.InterfaceGuid.data4);
    if guid == [0; 16] {
        return Err(invalid());
    }
    Ok(InterfaceRecord {
        proof: PhysicalProof {
            identity: InterfaceIdentity { index, luid, guid },
            family,
            metric: ip.Metric,
        },
        alias,
        if_type: row.Type,
        tunnel_type: row.TunnelType,
        oper_status: row.OperStatus,
        // SDK layout: HardwareInterface is bit 0, Filter bit 1, EndPoint bit 7.
        // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2
        status_flags: row.InterfaceAndOperStatusFlags._bitfield,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::{
        core::GUID,
        Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0, SOCKADDR_IN, SOCKADDR_INET},
    };

    fn raw_interface() -> (MIB_IF_ROW2, MIB_IPINTERFACE_ROW) {
        let mut row = MIB_IF_ROW2 {
            InterfaceIndex: 7,
            InterfaceLuid: NET_LUID_LH { Value: 700 },
            InterfaceGuid: GUID::from_u128(0x12345678_1234_4321_abcd_123456789abc),
            Type: 6,
            OperStatus: 1,
            ..Default::default()
        };
        row.InterfaceAndOperStatusFlags._bitfield = 1;
        row.Alias[..8].copy_from_slice(&[69, 116, 104, 101, 114, 110, 101, 116]);
        let ip = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceIndex: 7,
            InterfaceLuid: NET_LUID_LH { Value: 700 },
            Metric: 9,
            ..Default::default()
        };
        (row, ip)
    }

    #[test]
    fn decode_interface_retains_canonical_guid_identity_and_family_metric() {
        let (row, ip) = raw_interface();
        let record = decode_interface(&row, &ip, Family::V4, 7, 700).unwrap();
        assert_eq!(
            record.proof.identity.guid,
            0x12345678_1234_4321_abcd_123456789abcu128.to_be_bytes()
        );
        assert_eq!(record.proof.identity.index, 7);
        assert_eq!(record.proof.identity.luid, 700);
        assert_eq!(record.proof.metric, 9);
        assert_eq!(record.alias, "Ethernet");
        assert_eq!(record.status_flags, 1);
    }

    #[test]
    fn mismatched_interface_family_index_luid_and_invalid_alias_are_errors() {
        for mutation in 0..6 {
            let (mut row, mut ip) = raw_interface();
            match mutation {
                0 => ip.Family = AF_INET6,
                1 => row.InterfaceIndex = 8,
                2 => row.InterfaceLuid = NET_LUID_LH { Value: 701 },
                3 => ip.InterfaceLuid = NET_LUID_LH { Value: 701 },
                4 => row.Alias.fill(65),
                _ => row.Alias[0] = 0xd800,
            }
            assert!(decode_interface(&row, &ip, Family::V4, 7, 700).is_err());
        }
    }

    #[test]
    fn table_decoder_checks_null_count_and_family_before_returning_rows() {
        assert!(unsafe { decode_table(ptr::null(), Family::V4) }.is_err());
        let mut table = MIB_IPFORWARD_TABLE2::default();
        assert!(unsafe { decode_table(&table, Family::V4) }
            .unwrap()
            .is_empty());
        table.NumEntries = MAX_TABLE_ROWS as u32 + 1;
        assert!(unsafe { decode_table(&table, Family::V4) }.is_err());
        table.NumEntries = 1;
        let address = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: 0 },
                },
                ..Default::default()
            },
        };
        table.Table[0].InterfaceIndex = 7;
        table.Table[0].InterfaceLuid = NET_LUID_LH { Value: 700 };
        table.Table[0].DestinationPrefix.Prefix = address;
        table.Table[0].NextHop = address;
        table.Table[0].Metric = 19;
        table.Table[0].Protocol = 16;
        table.Table[0].ValidLifetime = 30;
        let rows = unsafe { decode_table(&table, Family::V4) }.unwrap();
        assert_eq!(rows[0].route.metric, 19);
        assert_eq!(rows[0].protocol, 16);
        assert_eq!(rows[0].valid_lifetime, 30);
        assert!(unsafe { decode_table(&table, Family::V6) }.is_err());
    }
}
