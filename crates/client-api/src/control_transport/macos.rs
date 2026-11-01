//! macOS physical control sockets, using read-only native service metadata.
use super::command;
use super::Interface;
#[cfg(target_os = "macos")]
use super::Snapshot;
use std::{
    collections::BTreeMap,
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6},
};
#[cfg(target_os = "macos")]
use std::{ffi::CStr, net::Ipv6Addr, num::NonZeroU32};
#[cfg(target_os = "macos")]
#[path = "macos_dns.rs"]
mod dns;

#[cfg(target_os = "macos")]
pub(super) fn snapshot() -> io::Result<Snapshot> {
    let hardware = parse_hardware(&command::run(
        "/usr/sbin/networksetup",
        &["-listallhardwareports"],
    )?)?;
    let links = native_links(&hardware)?;
    let ipv4 = select_route(
        &command::run("/usr/sbin/netstat", &["-rn", "-f", "inet"])?,
        &links,
        false,
    )?;
    let ipv6 = select_route(
        &command::run("/usr/sbin/netstat", &["-rn", "-f", "inet6"])?,
        &links,
        true,
    )?;
    let interfaces = [ipv4.clone(), ipv6.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if interfaces.is_empty() {
        return Err(unavailable());
    }
    for interface in &interfaces {
        verify_index(interface)?;
    }
    Ok(Snapshot { ipv4, ipv6 })
}
#[cfg(target_os = "macos")]
pub(super) fn resolve(host: &str, snapshot: &Snapshot) -> io::Result<Vec<IpAddr>> {
    dns::resolve(host, snapshot)
}

#[cfg(target_os = "macos")]
pub(super) fn bind_socket(
    socket: &socket2::Socket,
    interface: &Interface,
    remote: SocketAddr,
) -> io::Result<()> {
    verify_index(interface)?;
    if !interface
        .addresses
        .iter()
        .any(|a| a.is_ipv4() == remote.is_ipv4())
    {
        return Err(invalid());
    }
    let index = NonZeroU32::new(interface.index).ok_or_else(invalid)?;
    let existing = if remote.is_ipv4() {
        socket.device_index_v4()?
    } else {
        socket.device_index_v6()?
    };
    if existing.is_some() {
        return Err(invalid());
    }
    if remote.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))?;
    } else {
        socket.bind_device_by_index_v6(Some(index))?;
    }
    let actual = if remote.is_ipv4() {
        socket.device_index_v4()?
    } else {
        socket.device_index_v6()?
    };
    if actual != Some(index) {
        return Err(invalid());
    }
    verify_index(interface)
}

fn verify_index(interface: &Interface) -> io::Result<()> {
    let name = CString::new(interface.name.as_str()).map_err(|_| invalid())?;
    if interface.index == 0 || unsafe { libc::if_nametoindex(name.as_ptr()) } != interface.index {
        return Err(unavailable());
    }
    Ok(())
}
fn parse_hardware(text: &str) -> io::Result<BTreeMap<String, String>> {
    let mut hardware = BTreeMap::new();
    let mut port = None;
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Hardware Port: ") {
            port = Some(value.to_owned());
        } else if let Some(name) = line.strip_prefix("Device: ") {
            if name.is_empty()
                || name.len() >= libc::IFNAMSIZ
                || !name.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(invalid());
            }
            let port = port.take().ok_or_else(invalid)?;
            // Hardware enumeration includes the virtual Thunderbolt bridge.
            if [
                "lo", "utun", "tun", "tap", "bridge", "awdl", "llw", "gif", "stf",
            ]
            .iter()
            .any(|p| name.starts_with(p))
            {
                continue;
            }
            if hardware.insert(name.into(), port).is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(hardware)
}
#[cfg(target_os = "macos")]
fn native_links(hardware: &BTreeMap<String, String>) -> io::Result<BTreeMap<String, Interface>> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let mut first = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let addresses = Addresses(first);
    let mut row = addresses.0;
    let mut result = BTreeMap::new();
    while !row.is_null() {
        let value = unsafe { &*row };
        if !value.ifa_addr.is_null() && !value.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(value.ifa_name) }
                .to_str()
                .map_err(|_| invalid())?;
            if let Some(port) = hardware.get(name) {
                let flags = value.ifa_flags as i32;
                if flags & (libc::IFF_UP | libc::IFF_RUNNING) == (libc::IFF_UP | libc::IFF_RUNNING)
                    && flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) == 0
                    && unsafe { (*value.ifa_addr).sa_family as i32 } == libc::AF_LINK
                {
                    let link = unsafe {
                        std::ptr::read_unaligned(value.ifa_addr.cast::<libc::sockaddr_dl>())
                    };
                    if link.sdl_type != 6
                        || link.sdl_alen != 6
                        || usize::from(link.sdl_nlen) + 6 > link.sdl_data.len()
                    {
                        row = value.ifa_next;
                        continue;
                    }
                    let start = usize::from(link.sdl_nlen);
                    let mac = link.sdl_data[start..start + 6]
                        .iter()
                        .map(|b| format!("{:02x}", *b as u8))
                        .collect::<Vec<_>>()
                        .join(":");
                    let index = u32::from(link.sdl_index);
                    if index == 0
                        || result
                            .insert(
                                name.to_owned(),
                                Interface {
                                    index,
                                    name: name.into(),
                                    identity: format!("macos:{index}:{name}:{port}:{mac}"),
                                    addresses: vec![],
                                    gateway: None,
                                },
                            )
                            .is_some()
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        row = value.ifa_next;
    }
    row = addresses.0;
    while !row.is_null() {
        let value = unsafe { &*row };
        if !value.ifa_addr.is_null() && !value.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(value.ifa_name) }
                .to_str()
                .map_err(|_| invalid())?;
            if let Some(interface) = result.get_mut(name) {
                let address = match unsafe { (*value.ifa_addr).sa_family as i32 } {
                    libc::AF_INET => {
                        let v = unsafe {
                            std::ptr::read_unaligned(value.ifa_addr.cast::<libc::sockaddr_in>())
                        };
                        Some(IpAddr::V4(Ipv4Addr::from(v.sin_addr.s_addr.to_ne_bytes())))
                    }
                    libc::AF_INET6 => {
                        let v = unsafe {
                            std::ptr::read_unaligned(value.ifa_addr.cast::<libc::sockaddr_in6>())
                        };
                        Some(IpAddr::V6(Ipv6Addr::from(v.sin6_addr.s6_addr)))
                    }
                    _ => None,
                };
                if let Some(address) = address.filter(|a| valid_address(*a)) {
                    interface.addresses.push(address);
                }
            }
        }
        row = value.ifa_next;
    }
    result.retain(|_, i| {
        i.addresses.sort();
        i.addresses.dedup();
        !i.addresses.is_empty()
    });
    for interface in result.values() {
        verify_index(interface)?;
    }
    Ok(result)
}
fn select_route(
    text: &str,
    links: &BTreeMap<String, Interface>,
    ipv6: bool,
) -> io::Result<Option<Interface>> {
    let mut defaults = Vec::new();
    for fields in text
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|f| f.first() == Some(&"default"))
    {
        if fields.len() < 4 {
            return Err(invalid());
        }
        let Some(interface) = links.get(fields[3]) else {
            continue;
        };
        if !fields[2].contains('U') || fields[2].contains('R') || fields[2].contains('B') {
            return Err(invalid());
        }
        if !interface
            .addresses
            .iter()
            .any(|a| a.is_ipv6() == ipv6 && !matches!(a,IpAddr::V6(v) if v.is_unicast_link_local()))
        {
            continue;
        }
        let mut interface = interface.clone();
        interface.gateway = if let Some(index) = fields[1].strip_prefix("link#") {
            if index.parse::<u32>().ok() != Some(interface.index) {
                return Err(invalid());
            }
            None
        } else {
            let gateway = scoped_address(fields[1], &interface)?;
            if gateway.ip().is_ipv6() != ipv6 {
                return Err(invalid());
            }
            Some(gateway.ip())
        };
        defaults.push((fields[2].contains('I'), interface));
    }
    if defaults.iter().any(|r| !r.0) {
        defaults.retain(|r| !r.0);
    }
    defaults.dedup();
    if defaults.len() > 1 {
        return Err(io::Error::other("physical_egress_ambiguous"));
    }
    Ok(defaults.pop().map(|v| v.1))
}
fn scoped_address(text: &str, interface: &Interface) -> io::Result<SocketAddr> {
    let (text, scope) = match text.split_once('%') {
        Some((a, s)) => (a, Some(s)),
        None => (text, None),
    };
    let address = text.parse::<IpAddr>().map_err(|_| invalid())?;
    if !valid_address(address) {
        return Err(invalid());
    }
    if scope.is_some_and(|s| s != interface.name && s.parse::<u32>().ok() != Some(interface.index))
    {
        return Err(invalid());
    }
    Ok(match address {
        IpAddr::V6(v) if v.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(v, 53, 0, interface.index))
        }
        _ if scope.is_none() => SocketAddr::new(address, 53),
        _ => return Err(invalid()),
    })
}
fn valid_address(a: IpAddr) -> bool {
    !a.is_unspecified()
        && !a.is_loopback()
        && !a.is_multicast()
        && a != IpAddr::V4(Ipv4Addr::BROADCAST)
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "physical_network_state_invalid")
}
fn unavailable() -> io::Error {
    io::Error::other("physical_egress_unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn links() -> BTreeMap<String, Interface> {
        BTreeMap::from([
            (
                "en0".into(),
                Interface {
                    index: 6,
                    name: "en0".into(),
                    identity: "ether:00:11:22:33:44:55".into(),
                    addresses: vec![
                        "192.0.2.4".parse().unwrap(),
                        "2001:db8::4".parse().unwrap(),
                        "fe80::4".parse().unwrap(),
                    ],
                    gateway: None,
                },
            ),
            (
                "en1".into(),
                Interface {
                    index: 7,
                    name: "en1".into(),
                    identity: "ether:00:11:22:33:44:66".into(),
                    addresses: vec!["192.0.3.4".parse().unwrap()],
                    gateway: None,
                },
            ),
        ])
    }
    #[test]
    fn physical_default_prefers_unscoped_over_scoped_and_ignores_tunnel() {
        let table="Destination Gateway Flags Netif Expire\ndefault 10.7.0.1 UGSc utun4\ndefault 192.0.3.1 UGScI en1\ndefault 192.0.2.1 UGScg en0\n";
        assert_eq!(
            select_route(table, &links(), false).unwrap().unwrap().name,
            "en0"
        );
    }
    #[test]
    fn ambiguous_defaults_fail_closed() {
        assert!(select_route(
            "default 192.0.2.1 UGSc en0\ndefault 192.0.3.1 UGSc en1\n",
            &links(),
            false
        )
        .is_err());
    }
    #[test]
    fn scoped_ipv6_gateway_must_match_selected_interface() {
        assert_eq!(
            select_route("default fe80::1%en0 UGcIg en0\n", &links(), true)
                .unwrap()
                .unwrap()
                .gateway,
            Some("fe80::1".parse().unwrap())
        );
        assert!(select_route("default fe80::1%en1 UGcIg en0\n", &links(), true).is_err());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod native_tests {
    use super::*;
    #[test]
    fn native_socket_binding_is_read_back_for_both_families() {
        let name = CString::new("lo0").unwrap();
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0);
        let interface = Interface {
            index,
            name: "lo0".into(),
            identity: "test-loopback".into(),
            addresses: vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            gateway: None,
        };
        for remote in ["127.0.0.1:9", "[::1]:9"] {
            let remote: SocketAddr = remote.parse().unwrap();
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(remote),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )
            .unwrap();
            bind_socket(&socket, &interface, remote).unwrap();
            let readback = if remote.is_ipv4() {
                socket.device_index_v4()
            } else {
                socket.device_index_v6()
            };
            assert_eq!(readback.unwrap().map(NonZeroU32::get), Some(index));
            assert!(
                bind_socket(&socket, &interface, remote).is_err(),
                "already-bound sockets must not be repurposed"
            );
        }
    }
}
