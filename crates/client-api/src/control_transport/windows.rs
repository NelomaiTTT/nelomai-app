//! Read-only physical adapter discovery and per-socket Windows egress binding.
use super::{Interface, Snapshot};
use socket2::Socket;
use std::{
    collections::BTreeMap,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::windows::io::AsRawSocket,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, NO_ERROR},
    NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GetBestRoute2, GetIfEntry2, GetIpForwardTable2,
        GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    },
    Networking::WinSock::{
        getsockopt, setsockopt, WSAGetLastError, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR,
        IN6_ADDR_0, IN_ADDR, IN_ADDR_0, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF,
        SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET, SOCKET_ERROR,
    },
};

#[path = "windows_policy.rs"]
mod policy;

#[path = "windows_dns.rs"]
mod dns;
pub(super) fn resolve(host: &str, snapshot: &Snapshot) -> io::Result<Vec<IpAddr>> {
    dns::resolve(host, snapshot)
}

const MAX_ROWS: usize = 4096;
const MAX_ADAPTER_BYTES: usize = 1024 * 1024;

fn identity(guid: windows_sys::core::GUID, luid: u64) -> String {
    format!(
        "{luid:016x}:{:08x}{:04x}{:04x}{:016x}",
        guid.data1,
        guid.data2,
        guid.data3,
        u64::from_be_bytes(guid.data4)
    )
}

fn unavailable() -> io::Error {
    io::Error::other("physical_egress_unavailable")
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

struct Adapter {
    v4: u32,
    v6: u32,
    luid: u64,
    addresses: Vec<IpAddr>,
}

/// The native buffer owns all linked records and their string/address storage.
/// Its word backing preserves the SDK's alignment requirements.
struct AdapterMemory(Vec<u64>);
impl AdapterMemory {
    fn contains<T>(&self, pointer: *const T) -> io::Result<()> {
        let start = self.0.as_ptr() as usize;
        let address = pointer as usize;
        if pointer.is_null()
            || address % std::mem::align_of::<T>() != 0
            || address < start
            || address
                .checked_add(size_of::<T>())
                .is_none_or(|end| end > start + self.0.len() * 8)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn address(&self, pointer: *const SOCKADDR, length: i32, index: u32) -> io::Result<SocketAddr> {
        self.contains(pointer)?;
        if length < 0 {
            return Err(invalid());
        }
        let family = unsafe { (*pointer).sa_family };
        if family == AF_INET && length as usize >= size_of::<SOCKADDR_IN>() {
            self.contains(pointer.cast::<SOCKADDR_IN>())?;
            let value = unsafe { pointer.cast::<SOCKADDR_IN>().read() };
            Ok(SocketAddr::new(
                Ipv4Addr::from(unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes()).into(),
                u16::from_be(value.sin_port),
            ))
        } else if family == AF_INET6 && length as usize >= size_of::<SOCKADDR_IN6>() {
            self.contains(pointer.cast::<SOCKADDR_IN6>())?;
            let value = unsafe { pointer.cast::<SOCKADDR_IN6>().read() };
            let ip = Ipv6Addr::from(unsafe { value.sin6_addr.u.Byte });
            let scope = unsafe { value.Anonymous.sin6_scope_id };
            if value.sin6_flowinfo != 0
                || (scope != 0 && (!ip.is_unicast_link_local() || scope != index))
            {
                return Err(invalid());
            }
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(value.sin6_port),
                0,
                if ip.is_unicast_link_local() { index } else { 0 },
            )))
        } else {
            Err(invalid())
        }
    }
}

fn adapters() -> io::Result<Vec<Adapter>> {
    let mut memory = AdapterMemory(vec![0u64; 2048]);
    let mut success = false;
    for _ in 0..3 {
        let mut bytes = u32::try_from(memory.0.len() * 8).map_err(|_| invalid())?;
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                0,
                ptr::null(),
                memory.0.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if code == NO_ERROR {
            success = true;
            break;
        }
        if code != ERROR_BUFFER_OVERFLOW {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        if bytes as usize > MAX_ADAPTER_BYTES {
            return Err(invalid());
        }
        memory.0.resize((bytes as usize).div_ceil(8), 0);
    }
    if !success {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut next = memory.0.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        if result.len() == MAX_ROWS {
            return Err(invalid());
        }
        memory.contains(next)?;
        let raw = unsafe { &*next };
        let index = unsafe { raw.Anonymous1.Anonymous.IfIndex };
        let mut addresses = Vec::new();
        let mut unicast = raw.FirstUnicastAddress;
        let mut count = 0;
        while !unicast.is_null() {
            if count == MAX_ROWS {
                return Err(invalid());
            }
            count += 1;
            memory.contains(unicast)?;
            let row = unsafe { &*unicast };
            let family = if row.Address.lpSockaddr.is_null() {
                return Err(invalid());
            } else {
                memory.contains(row.Address.lpSockaddr)?;
                unsafe { (*row.Address.lpSockaddr).sa_family }
            };
            let address = memory.address(
                row.Address.lpSockaddr,
                row.Address.iSockaddrLength,
                if family == AF_INET6 {
                    raw.Ipv6IfIndex
                } else {
                    index
                },
            )?;
            // IpDadStatePreferred. Tentative/deprecated/duplicate addresses are never sources.
            if row.DadState == 4
                && row.ValidLifetime != 0
                && row.PreferredLifetime != 0
                && policy::usable(address.ip())
            {
                addresses.push(address.ip());
            }
            unicast = row.Next;
        }
        addresses.sort();
        addresses.dedup();
        result.push(Adapter {
            v4: index,
            v6: raw.Ipv6IfIndex,
            luid: unsafe { raw.Luid.Value },
            addresses,
        });
        next = raw.Next;
    }
    Ok(result)
}

struct RouteMemory(*mut MIB_IPFORWARD_TABLE2);
impl Drop for RouteMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
}
fn routes(family: u16) -> io::Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut raw = ptr::null_mut();
    let code = unsafe { GetIpForwardTable2(family, &mut raw) };
    let memory = RouteMemory(raw);
    if code == ERROR_NOT_FOUND {
        return Ok(Vec::new());
    }
    status(code)?;
    if memory.0.is_null() {
        return Err(invalid());
    }
    let count = unsafe { ptr::addr_of!((*memory.0).NumEntries).read() } as usize;
    if count > MAX_ROWS {
        return Err(invalid());
    }
    let start = unsafe { ptr::addr_of!((*memory.0).Table).cast::<MIB_IPFORWARD_ROW2>() };
    Ok(unsafe { std::slice::from_raw_parts(start, count) }.to_vec())
}

fn interface(
    index: u32,
    luid: u64,
    family: u16,
    addresses: &[IpAddr],
) -> io::Result<Option<(Interface, u32)>> {
    let mut row = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut row) })?;
    if index == 0
        || luid == 0
        || row.InterfaceIndex != index
        || unsafe { row.InterfaceLuid.Value } != luid
    {
        return Err(invalid());
    }
    let end = row
        .Alias
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(invalid)?;
    let name = String::from_utf16(&row.Alias[..end]).map_err(|_| invalid())?;
    if !policy::physical(
        row.Type,
        row.TunnelType,
        row.OperStatus,
        row.InterfaceAndOperStatusFlags._bitfield,
        &name,
    ) {
        return Ok(None);
    }
    let guid = row.InterfaceGuid;
    if guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8] {
        return Err(invalid());
    }
    let identity = identity(guid, luid);
    let mut ip = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceIndex: index,
        InterfaceLuid: row.InterfaceLuid,
        ..Default::default()
    };
    status(unsafe { GetIpInterfaceEntry(&mut ip) })?;
    if ip.InterfaceIndex != index
        || unsafe { ip.InterfaceLuid.Value } != luid
        || ip.Family != family
        || !ip.Connected
        || ip.DisableDefaultRoutes
    {
        return Ok(None);
    }
    let mut after = MIB_IF_ROW2 {
        InterfaceIndex: index,
        ..Default::default()
    };
    status(unsafe { GetIfEntry2(&mut after) })?;
    let after_guid = after.InterfaceGuid;
    if after.InterfaceIndex != index
        || unsafe { after.InterfaceLuid.Value } != luid
        || (
            after_guid.data1,
            after_guid.data2,
            after_guid.data3,
            after_guid.data4,
        ) != (guid.data1, guid.data2, guid.data3, guid.data4)
        || after.Type != row.Type
        || after.TunnelType != row.TunnelType
        || after.OperStatus != row.OperStatus
        || after.InterfaceAndOperStatusFlags._bitfield != row.InterfaceAndOperStatusFlags._bitfield
        || after.Alias != row.Alias
    {
        return Err(invalid());
    }
    Ok(Some((
        Interface {
            index,
            name,
            identity,
            addresses: addresses.to_vec(),
            gateway: None,
        },
        ip.Metric,
    )))
}

pub(super) fn snapshot() -> io::Result<Snapshot> {
    let adapters = adapters()?;
    let mut selected = [None, None];
    for (slot, family) in [AF_INET, AF_INET6].into_iter().enumerate() {
        let mut interfaces = BTreeMap::new();
        for adapter in &adapters {
            let index = if family == AF_INET {
                adapter.v4
            } else {
                adapter.v6
            };
            if index == 0
                || !adapter
                    .addresses
                    .iter()
                    .any(|ip| ip.is_ipv4() == (family == AF_INET))
            {
                continue;
            }
            if let Some(proof) = interface(index, adapter.luid, family, &adapter.addresses)? {
                if interfaces.insert(index, (proof, adapter)).is_some() {
                    return Err(invalid());
                }
            }
        }
        let mut candidates = Vec::new();
        for row in routes(family)? {
            if row.DestinationPrefix.PrefixLength != 0 || row.Loopback || row.ValidLifetime == 0 {
                continue;
            }
            let Some(((interface, metric), adapter)) = interfaces.get(&row.InterfaceIndex) else {
                continue;
            };
            let destination = decode(&row.DestinationPrefix.Prefix)?;
            if unsafe { row.InterfaceLuid.Value } != adapter.luid
                || !destination.is_unspecified()
                || destination.is_ipv4() != (family == AF_INET)
            {
                return Err(invalid());
            }
            let gateway = decode(&row.NextHop)?;
            if gateway.is_ipv4() != (family == AF_INET)
                || (!gateway.is_unspecified() && !policy::usable(gateway))
            {
                return Err(invalid());
            }
            candidates.push(policy::Candidate {
                index: interface.index,
                metric: u64::from(row.Metric) + u64::from(*metric),
                gateway: (!gateway.is_unspecified()).then_some(gateway),
            });
        }
        if let Some(best) = policy::select(&candidates)? {
            let ((mut interface, _), _) = interfaces.remove(&best.index).ok_or_else(invalid)?;
            interface.gateway = best.gateway;
            selected[slot] = Some(interface);
        }
    }
    let [ipv4, ipv6] = selected;
    if ipv4.is_none() && ipv6.is_none() {
        return Err(unavailable());
    }
    Ok(Snapshot { ipv4, ipv6 })
}

fn decode(address: &SOCKADDR_INET) -> io::Result<IpAddr> {
    match unsafe { address.si_family } {
        AF_INET => {
            Ok(Ipv4Addr::from(unsafe { address.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes()).into())
        }
        AF_INET6 => Ok(Ipv6Addr::from(unsafe { address.Ipv6.sin6_addr.u.Byte }).into()),
        _ => Err(invalid()),
    }
}
fn encode(address: SocketAddr) -> SOCKADDR_INET {
    match address {
        SocketAddr::V4(value) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: value.port().to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(value.ip().octets()),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        SocketAddr::V6(value) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: value.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 {
                        Byte: value.ip().octets(),
                    },
                },
                Anonymous: SOCKADDR_IN6_0 {
                    sin6_scope_id: value.scope_id(),
                },
            },
        },
    }
}

fn set_interface(socket: &Socket, family: u16, index: u32) -> io::Result<()> {
    if index == 0 {
        return Err(invalid());
    }
    let (level, option, value) = if family == AF_INET {
        (
            IPPROTO_IP,
            IP_UNICAST_IF,
            policy::interface_value(true, index),
        )
    } else if family == AF_INET6 {
        (
            IPPROTO_IPV6,
            IPV6_UNICAST_IF,
            policy::interface_value(false, index),
        )
    } else {
        return Err(invalid());
    };
    let raw = socket.as_raw_socket() as _;
    if unsafe {
        setsockopt(
            raw,
            level,
            option,
            (&value as *const u32).cast(),
            size_of::<u32>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let mut actual = 0u32;
    let mut length = size_of::<u32>() as i32;
    if unsafe {
        getsockopt(
            raw,
            level,
            option,
            (&mut actual as *mut u32).cast(),
            &mut length,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    if length != size_of::<u32>() as i32 || actual != index {
        return Err(invalid());
    }
    Ok(())
}

fn verify_target_route(chosen: &MIB_IPFORWARD_ROW2, remote: SocketAddr) -> io::Result<()> {
    let mut matching = Vec::new();
    for row in routes(if remote.is_ipv4() { AF_INET } else { AF_INET6 })? {
        if row.InterfaceIndex != chosen.InterfaceIndex
            || unsafe { row.InterfaceLuid.Value } != unsafe { chosen.InterfaceLuid.Value }
            || row.Loopback
            || row.ValidLifetime == 0
        {
            continue;
        }
        if policy::covers(
            decode(&row.DestinationPrefix.Prefix)?,
            row.DestinationPrefix.PrefixLength,
            remote.ip(),
        ) {
            matching.push(row);
        }
    }
    let prefix = matching
        .iter()
        .map(|row| row.DestinationPrefix.PrefixLength)
        .max()
        .ok_or_else(unavailable)?;
    let candidates: Vec<_> = matching
        .iter()
        .filter(|row| row.DestinationPrefix.PrefixLength == prefix)
        .map(|row| {
            Ok(policy::Candidate {
                index: row.InterfaceIndex,
                metric: u64::from(row.Metric),
                gateway: Some(decode(&row.NextHop)?),
            })
        })
        .collect::<io::Result<_>>()?;
    let best = policy::select(&candidates)?.ok_or_else(unavailable)?;
    if chosen.DestinationPrefix.PrefixLength != prefix
        || u64::from(chosen.Metric) != best.metric
        || Some(decode(&chosen.NextHop)?) != best.gateway
    {
        return Err(io::Error::other("physical_route_or_identity_changed"));
    }
    Ok(())
}

pub(super) fn bind_socket(
    socket: &Socket,
    expected: &Interface,
    remote: SocketAddr,
) -> io::Result<()> {
    if !policy::usable(remote.ip()) || remote.port() == 0 {
        return Err(invalid());
    }
    if let SocketAddr::V6(address) = remote {
        if address.flowinfo() != 0
            || (address.scope_id() != 0
                && (!address.ip().is_unicast_link_local() || address.scope_id() != expected.index))
        {
            return Err(invalid());
        }
    }
    let current = snapshot()?;
    if current.interface(remote.ip())? != expected {
        return Err(io::Error::other("physical_route_or_identity_changed"));
    }
    let mut route_destination = remote;
    route_destination.set_port(0);
    let destination = encode(route_destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    status(unsafe {
        GetBestRoute2(
            ptr::null(),
            expected.index,
            ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    })?;
    let ip = decode(&source)?;
    if route.InterfaceIndex != expected.index
        || route.Loopback
        || route.ValidLifetime == 0
        || ip.is_ipv4() != remote.is_ipv4()
        || !policy::usable(ip)
        || !expected.addresses.contains(&ip)
    {
        return Err(invalid());
    }
    verify_target_route(&route, remote)?;
    // Recheck identity after the route/source lookup; never follow a recycled index.
    let family = if remote.is_ipv4() { AF_INET } else { AF_INET6 };
    let Some((proof, _)) = interface(
        expected.index,
        unsafe { route.InterfaceLuid.Value },
        family,
        &expected.addresses,
    )?
    else {
        return Err(unavailable());
    };
    if proof.identity != expected.identity || proof.name != expected.name {
        return Err(invalid());
    }
    let local = match ip {
        IpAddr::V4(_) => SocketAddr::new(ip, 0),
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(
            ip,
            0,
            0,
            if ip.is_unicast_link_local() {
                expected.index
            } else {
                0
            },
        )),
    };
    socket.bind(&local.into())?;
    set_interface(socket, family, expected.index)?;
    if socket
        .local_addr()?
        .as_socket()
        .is_none_or(|actual| actual.ip() != ip)
    {
        return Err(invalid());
    }
    let Some((after, _)) = interface(
        expected.index,
        unsafe { route.InterfaceLuid.Value },
        family,
        &expected.addresses,
    )?
    else {
        return Err(unavailable());
    };
    if after.identity != expected.identity || after.name != expected.name {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_sockaddr_roundtrips_both_families() {
        for address in ["192.0.2.1:53", "[2001:db8::1]:443", "[fe80::1%7]:53"] {
            let address: SocketAddr = address.parse().unwrap();
            assert_eq!(decode(&encode(address)).unwrap(), address.ip());
        }
    }
    #[test]
    fn native_interface_option_readback_without_network_traffic() {
        // Real Winsock calls, no connection, packets or network configuration writes.
        let index = routes(AF_INET)
            .unwrap()
            .into_iter()
            .find(|row| decode(&row.DestinationPrefix.Prefix).is_ok_and(|ip| ip.is_loopback()))
            .expect("Windows loopback route")
            .InterfaceIndex;
        for (family, domain) in [
            (AF_INET, socket2::Domain::IPV4),
            (AF_INET6, socket2::Domain::IPV6),
        ] {
            let socket =
                Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).unwrap();
            set_interface(&socket, family, index).unwrap();
        }
    }
}
