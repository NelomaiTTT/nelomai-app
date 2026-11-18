use super::{invalid, RouteAction};
use ipnet::IpNet;
use nelomai_client_tunnel::redundancy::network::{RouteScope, RouteValue};
use std::{
    ffi::CStr,
    io,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
    sync::atomic::{AtomicI32, Ordering},
    time::{Duration, Instant},
};

// The Darwin SDK defines NET_RT_DUMP2 as 7 (libc 0.2.189 lacks the constant).
const NET_RT_DUMP2: libc::c_int = 7;
const MAX_DUMP_BYTES: usize = 16 * 1024 * 1024;
const SOCKADDR_COUNT: usize = libc::RTAX_MAX as usize;
const GET_REPLY_TIMEOUT: Duration = Duration::from_secs(1);
static GET_SEQUENCE: AtomicI32 = AtomicI32::new(1);

pub(super) fn read_routes(
    ipv4: bool,
    keys: &[(IpNet, RouteScope)],
) -> io::Result<Vec<Option<RouteValue>>> {
    find_routes(&snapshot(ipv4)?, keys)
}

fn snapshot(ipv4: bool) -> io::Result<Vec<u8>> {
    let family = if ipv4 { libc::AF_INET } else { libc::AF_INET6 };
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, family, NET_RT_DUMP2, 0];
    // The table can grow between sizing and retrieval, including from
    // other apps. Retry with a fresh size rather than reading a partial dump.
    for _ in 0..4 {
        let mut len = 0;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                ptr::null_mut(),
                &mut len,
                ptr::null_mut(),
                0,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_DUMP_BYTES {
            return Err(invalid());
        }
        let mut snapshot = Vec::<u8>::with_capacity(len);
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                snapshot.as_mut_ptr().cast(),
                &mut len,
                ptr::null_mut(),
                0,
            )
        } == 0
        {
            if len > snapshot.capacity() {
                return Err(invalid());
            }
            // On success sysctl initialized exactly len bytes.
            unsafe { snapshot.set_len(len) };
            return Ok(snapshot);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("native_route_table_changed"))
}

#[derive(Clone)]
struct RouteRow {
    value: RouteValue,
    flags: i32,
}

fn find_routes(
    snapshot: &[u8],
    keys: &[(IpNet, RouteScope)],
) -> io::Result<Vec<Option<RouteValue>>> {
    Ok(find_rows(snapshot, keys)?
        .into_iter()
        .map(|row| row.map(|row| row.value))
        .collect())
}

fn find_rows(
    mut snapshot: &[u8],
    keys: &[(IpNet, RouteScope)],
) -> io::Result<Vec<Option<RouteRow>>> {
    use libc::rt_msghdr2 as Header;

    let mut results = vec![None; keys.len()];
    while !snapshot.is_empty() {
        if snapshot.len() < size_of::<Header>() {
            return Err(invalid());
        }
        let len = get_u16(snapshot, 0) as usize;
        if len < size_of::<Header>()
            || len > snapshot.len()
            || snapshot[2] != libc::RTM_VERSION as u8
            || snapshot[3] != libc::RTM_GET2 as u8
        {
            return Err(invalid());
        }
        let (row, rest) = snapshot.split_at(len);
        snapshot = rest;
        let interface = u32::from(get_u16(row, offset_of!(Header, rtm_index)));
        let flags = get_i32(row, offset_of!(Header, rtm_flags));
        let parent_flags = get_i32(row, offset_of!(Header, rtm_parentflags));
        let addrs = get_i32(row, offset_of!(Header, rtm_addrs));
        let host = flags & libc::RTF_HOST != 0;
        let has_mask = addrs & libc::RTA_NETMASK != 0;
        // Explicit routes can replace protocol clones. The latter are
        // also omitted by netstat -rn.
        if flags & libc::RTF_WASCLONED != 0 && parent_flags & libc::RTF_PRCLONING != 0 {
            continue;
        }
        let scope = if flags & libc::RTF_IFSCOPE != 0 {
            RouteScope::Member(interface)
        } else {
            RouteScope::Global
        };
        if !keys.iter().any(|(_, key_scope)| *key_scope == scope) {
            continue;
        }
        let fields = sockaddrs(&row[size_of::<Header>()..], addrs)?;
        let ip = ip_address(fields[0].ok_or_else(invalid)?)?;
        let prefix = if host || !has_mask {
            if ip.is_ipv4() {
                32
            } else {
                128
            }
        } else {
            let Some(prefix) = prefix(fields[2].ok_or_else(invalid)?, ip.is_ipv4()) else {
                // XNU also stores radix masks that have no matching IpNet key.
                continue;
            };
            prefix
        };
        let destination = IpNet::new(ip, prefix).map_err(|_| invalid())?.trunc();
        for (index, _) in keys
            .iter()
            .enumerate()
            .filter(|(_, key)| **key == (destination, scope))
        {
            if (!host && !has_mask)
                || interface == 0
                || results[index].is_some()
                || flags & libc::RTF_UP == 0
                || flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE) != 0
            {
                return Err(invalid());
            }
            let gateway = read_gateway(fields[1].ok_or_else(invalid)?, flags, interface)?;
            results[index] = Some(RouteRow {
                value: RouteValue {
                    destination,
                    scope,
                    interface,
                    gateway,
                    metric: 0,
                },
                flags,
            });
        }
    }
    Ok(results)
}

fn sockaddrs(mut bytes: &[u8], bits: i32) -> io::Result<[Option<&[u8]>; SOCKADDR_COUNT]> {
    let mut result = [None; SOCKADDR_COUNT];
    for (bit, address) in result.iter_mut().enumerate() {
        if bits & (1 << bit) != 0 {
            let len = usize::from(*bytes.first().ok_or_else(invalid)?);
            *address = Some(bytes.get(..len).ok_or_else(invalid)?);
            bytes = bytes.get(aligned_len(len)..).ok_or_else(invalid)?;
        }
    }
    Ok(result)
}

fn ip_address(bytes: &[u8]) -> io::Result<IpAddr> {
    match bytes.get(1).copied().map(i32::from) {
        Some(libc::AF_INET) if bytes.len() >= 8 => {
            Ok(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]).into())
        }
        Some(libc::AF_INET6) if bytes.len() >= 24 => {
            let mut bytes: [u8; 16] = bytes[8..24].try_into().expect("IPv6 address");
            // The kernel can embed an interface zone in link-local addresses.
            // Scope of a route row is kept separately in rtm_flags and rtm_index.
            if Ipv6Addr::from(bytes).is_unicast_link_local() {
                bytes[2..4].fill(0);
            }
            Ok(Ipv6Addr::from(bytes).into())
        }
        _ => Err(invalid()),
    }
}

fn read_gateway(gateway: &[u8], flags: i32, interface: u32) -> io::Result<Option<IpAddr>> {
    if gateway.get(1) == Some(&(libc::AF_LINK as u8)) && flags & libc::RTF_GATEWAY == 0 {
        if gateway.len() < 8 || gateway[6] != 0 || gateway[7] != 0 {
            return Err(invalid());
        }
        let link_index = u32::from(get_u16(gateway, 2));
        if link_index != 0 && link_index != interface {
            return Err(invalid());
        }
        let name = gateway
            .get(8..8 + usize::from(gateway[5]))
            .ok_or_else(invalid)?;
        if !name.is_empty() {
            let mut expected = [0; libc::IF_NAMESIZE];
            if unsafe { libc::if_indextoname(interface, expected.as_mut_ptr()) }.is_null()
                || unsafe { CStr::from_ptr(expected.as_ptr()) }.to_bytes() != name
            {
                return Err(invalid());
            }
        }
        return Ok(None);
    }
    let ip = ip_address(gateway)?;
    if matches!(ip, IpAddr::V6(address) if address.is_unicast_link_local()) {
        let embedded = u32::from(u16::from_be_bytes([gateway[10], gateway[11]]));
        let zone = gateway.get(24..28).map_or(0, |zone| {
            u32::from_ne_bytes(zone.try_into().expect("IPv6 zone"))
        });
        if [embedded, zone]
            .into_iter()
            .any(|zone| zone != 0 && zone != interface)
        {
            return Err(invalid());
        }
    }
    Ok(Some(ip))
}

fn prefix(mask: &[u8], ipv4: bool) -> Option<u8> {
    let (offset, len) = if ipv4 { (4, 4) } else { (8, 16) };
    // Darwin omits trailing zero bytes of a netmask and uses sa_len=0 for /0.
    let mut result = 0;
    let mut zeros = false;
    for index in offset..(offset + len) {
        let byte = mask.get(index).copied().unwrap_or(0);
        let ones = byte.leading_ones() as u8;
        if byte.count_ones() != u32::from(ones) || (zeros && ones != 0) {
            return None;
        }
        result += ones;
        zeros |= ones != 8;
    }
    Some(result)
}

fn host_prefix(destination: IpNet) -> bool {
    destination.prefix_len()
        == if destination.addr().is_ipv4() {
            32
        } else {
            128
        }
}

fn uses_host_flag(route: &RouteValue) -> bool {
    // A global IPv4 route with an explicit /32 has a different native
    // key from the RTF_HOST rows used by interface-bound probes.
    host_prefix(route.destination)
        && (route.scope != RouteScope::Global || route.destination.addr().is_ipv6())
}

pub(super) fn check_route_before(action: RouteAction, previous: &RouteValue) -> io::Result<()> {
    match action {
        RouteAction::Change => check_change_target(previous),
        RouteAction::Delete => {
            let snapshot = snapshot(previous.destination.addr().is_ipv4())?;
            check_delete_owner(&snapshot, previous)
        }
        RouteAction::Add => Ok(()),
    }
}

fn check_delete_owner(snapshot: &[u8], previous: &RouteValue) -> io::Result<()> {
    // Keep nonstatic and legacy forms visible to observers. Deleting a live
    // route requires the static flag and native form this adapter installs.
    let mask = libc::RTF_STATIC | libc::RTF_HOST;
    let expected = libc::RTF_STATIC
        | if uses_host_flag(previous) {
            libc::RTF_HOST
        } else {
            0
        };
    let owned = find_rows(snapshot, &[(previous.destination, previous.scope)])?
        .into_iter()
        .flatten()
        .any(|row| row.value == *previous && row.flags & mask == expected);
    if !owned {
        return Err(io::Error::other("native_route_ownership_changed"));
    }
    Ok(())
}

fn check_change_target(previous: &RouteValue) -> io::Result<()> {
    use libc::rt_msghdr as Header;

    if previous.scope != RouteScope::Global {
        return Err(invalid());
    }
    // XNU shares the RTM_GET and RTM_CHANGE lookup. The dump's egress
    // index cannot tell us the scope of the route that lookup would select.
    let mut request = message(libc::RTM_GET, previous, None)?;
    let pid = unsafe { libc::getpid() };
    let seq = GET_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    put(&mut request, offset_of!(Header, rtm_seq), seq.to_ne_bytes());

    let socket = open_route_socket()?;
    let fd = socket.as_raw_fd();
    send(fd, &request)?;

    let deadline = Instant::now() + GET_REPLY_TIMEOUT;
    let mut buffer = [0u8; size_of::<Header>() + SOCKADDR_COUNT * 256];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native_route_get_timeout",
            ));
        }
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let events = unsafe { libc::poll(&mut ready, 1, remaining.as_millis().max(1) as _) };
        if events < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if events == 0 {
            continue;
        }
        if ready.revents & libc::POLLIN == 0 {
            return Err(io::Error::other("native_route_get_socket_error"));
        }
        let len = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if len < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        if validate_get_reply(&buffer[..len as usize], pid, seq, previous)? {
            return Ok(());
        }
    }
}

// Only the response to our request can authorize a change.
fn validate_get_reply(
    packet: &[u8],
    pid: i32,
    seq: i32,
    previous: &RouteValue,
) -> io::Result<bool> {
    use libc::rt_msghdr as Header;

    if packet.len() < size_of::<Header>()
        || packet[3] != libc::RTM_GET as u8
        || get_i32(packet, offset_of!(Header, rtm_pid)) != pid
        || get_i32(packet, offset_of!(Header, rtm_seq)) != seq
    {
        return Ok(false);
    }
    if get_u16(packet, 0) as usize != packet.len() || packet[2] != libc::RTM_VERSION as u8 {
        return Err(invalid());
    }
    let errno = get_i32(packet, offset_of!(Header, rtm_errno));
    if errno != 0 {
        return Err(io::Error::from_raw_os_error(errno));
    }
    let flags = get_i32(packet, offset_of!(Header, rtm_flags));
    if flags & libc::RTF_IFSCOPE != 0 {
        return Err(io::Error::other("native_scoped_route_conflict"));
    }
    let required = libc::RTF_DONE | libc::RTF_UP | libc::RTF_STATIC;
    let forbidden =
        libc::RTF_REJECT | libc::RTF_BLACKHOLE | libc::RTF_WASCLONED | libc::RTF_CONDEMNED;
    let interface = u32::from(get_u16(packet, offset_of!(Header, rtm_index)));
    let host = flags & libc::RTF_HOST != 0;
    let fields = sockaddrs(
        &packet[size_of::<Header>()..],
        get_i32(packet, offset_of!(Header, rtm_addrs)),
    )?;
    let destination = previous.destination;
    let mask_matches = if host {
        fields[2].is_none()
    } else {
        fields[2].and_then(|mask| prefix(mask, destination.addr().is_ipv4()))
            == Some(destination.prefix_len())
    };
    if flags & required != required
        || flags & forbidden != 0
        || interface != previous.interface
        || host != uses_host_flag(previous)
        || !mask_matches
        || ip_address(fields[0].ok_or_else(invalid)?)? != destination.network()
        || read_gateway(fields[1].ok_or_else(invalid)?, flags, interface)? != previous.gateway
    {
        return Err(io::Error::other("native_route_ownership_changed"));
    }
    Ok(true)
}

pub(super) fn mutate(action: RouteAction, route: &RouteValue, name: &str) -> io::Result<()> {
    let link = link_address(route.interface, name)?;
    let kind = match action {
        RouteAction::Add => libc::RTM_ADD,
        RouteAction::Change => libc::RTM_CHANGE,
        RouteAction::Delete => libc::RTM_DELETE,
    };
    let packet = message(kind, route, Some(&link))?;
    let socket = open_route_socket()?;
    let fd = socket.as_raw_fd();
    // A routing write reports its result synchronously. This socket does
    // not consume replies.
    let disabled: libc::c_int = 0;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_USELOOPBACK,
            (&disabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    send(fd, &packet)
}

fn open_route_socket() -> io::Result<OwnedFd> {
    let raw = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn send(fd: libc::c_int, packet: &[u8]) -> io::Result<()> {
    match unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) } {
        written if written == packet.len() as isize => Ok(()),
        written if written < 0 => Err(io::Error::last_os_error()),
        _ => Err(io::ErrorKind::WriteZero.into()),
    }
}

fn link_address(index: u32, name: &str) -> io::Result<Vec<u8>> {
    struct Interfaces(*mut libc::ifaddrs);
    impl Drop for Interfaces {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut interfaces = Interfaces(ptr::null_mut());
    if unsafe { libc::getifaddrs(&mut interfaces.0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut next = interfaces.0;
    while let Some(ifa) = unsafe { next.as_ref() } {
        next = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        let header = unsafe { std::slice::from_raw_parts(ifa.ifa_addr.cast::<u8>(), 2) };
        if header[1] != libc::AF_LINK as u8 || header[0] < 8 {
            continue;
        }
        if unsafe { CStr::from_ptr(ifa.ifa_name) }.to_bytes() != name.as_bytes() {
            continue;
        }
        // The list from getifaddrs owns this complete variable-length address.
        let bytes =
            unsafe { std::slice::from_raw_parts(ifa.ifa_addr.cast(), usize::from(header[0])) };
        if u32::from(get_u16(bytes, 2)) == index {
            return Ok(bytes.to_vec());
        }
    }
    Err(invalid())
}

fn message(kind: i32, route: &RouteValue, link: Option<&[u8]>) -> io::Result<Vec<u8>> {
    use libc::rt_msghdr as Header;

    let mask = match route.destination {
        IpNet::V4(net) => IpAddr::V4(net.netmask()),
        IpNet::V6(net) => IpAddr::V6(net.netmask()),
    };
    let host = uses_host_flag(route);
    let mut flags = libc::RTF_UP | libc::RTF_STATIC;
    if host {
        flags |= libc::RTF_HOST;
    }
    let scope = match route.scope {
        RouteScope::Global => 0,
        RouteScope::Member(index) if index == route.interface => {
            flags |= libc::RTF_IFSCOPE;
            u16::try_from(index).map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    let mut bytes = vec![0; size_of::<Header>()];
    let mut bits = libc::RTA_DST;
    append_address(&mut bytes, &address(route.destination.network()));
    if let Some(link) = link {
        bits |= libc::RTA_GATEWAY;
        append_address(&mut bytes, link);
    }
    if !host {
        bits |= libc::RTA_NETMASK;
        let mut address = address(mask);
        address[..2].fill(0);
        let len = address
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |index| index + 1);
        // Family zero matches the compact mask emitted by Darwin route(8).
        let len = len.max(2);
        address[0] = len as u8;
        append_address(&mut bytes, &address[..len]);
    }
    let len = u16::try_from(bytes.len()).map_err(|_| invalid())?;
    put(&mut bytes, 0, len.to_ne_bytes());
    bytes[2] = libc::RTM_VERSION as u8;
    bytes[3] = kind as u8;
    put(
        &mut bytes,
        offset_of!(Header, rtm_index),
        scope.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(Header, rtm_flags),
        flags.to_ne_bytes(),
    );
    put(
        &mut bytes,
        offset_of!(Header, rtm_addrs),
        bits.to_ne_bytes(),
    );
    Ok(bytes)
}

fn address(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let mut bytes = vec![0; size_of::<libc::sockaddr_in>()];
            bytes[0] = bytes.len() as u8;
            bytes[1] = libc::AF_INET as u8;
            put(&mut bytes, 4, ip.octets());
            bytes
        }
        IpAddr::V6(ip) => {
            let mut bytes = vec![0; size_of::<libc::sockaddr_in6>()];
            bytes[0] = bytes.len() as u8;
            bytes[1] = libc::AF_INET6 as u8;
            put(&mut bytes, 8, ip.octets());
            bytes
        }
    }
}

fn aligned_len(len: usize) -> usize {
    len.max(4).next_multiple_of(4)
}

fn append_address(bytes: &mut Vec<u8>, address: &[u8]) {
    bytes.extend_from_slice(address);
    bytes.resize(bytes.len() + aligned_len(address.len()) - address.len(), 0);
}

fn put<const N: usize>(bytes: &mut [u8], offset: usize, value: [u8; N]) {
    bytes[offset..offset + N].copy_from_slice(&value);
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
}

fn get_i32(bytes: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(bytes[offset..offset + 4].try_into().expect("i32 field"))
}

#[cfg(test)]
#[path = "routing_tests.rs"]
mod tests;
