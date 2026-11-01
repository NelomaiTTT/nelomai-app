//! Linux physical control sockets. Discovery never changes routes or resolver state.
use super::command;
#[cfg(target_os = "linux")]
use super::DnsServer;
use super::{Interface, Snapshot};
use serde_json::{Map, Value};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    io,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};
#[path = "linux_dns.rs"]
mod dns;

pub(super) fn snapshot() -> io::Result<Snapshot> {
    let ip = executable("ip")?;
    let link_text = command::run(ip, &["-j", "-d", "link", "show"])?;
    let mut devices = BTreeMap::new();
    for row in rows(&link_text)? {
        let name = text(object(&row)?, "ifname")?;
        valid_name(name)?;
        let path = Path::new("/sys/class/net").join(name).join("device");
        if let Ok(device) = path.canonicalize() {
            devices.insert(name.to_owned(), device.to_string_lossy().into_owned());
        }
    }
    let links = parse_links(
        &link_text,
        &command::run(ip, &["-j", "addr", "show"])?,
        &devices,
    )?;
    let mut selected = Vec::new();
    for (family, ipv6) in [("-4", false), ("-6", true)] {
        let route_text = command::run(ip, &["-j", "-N", family, "route", "show", "table", "main"])?;
        let interface = select_route(&route_text, &links, ipv6)?;
        if let Some(ref interface) = interface {
            verify_rules(
                &command::run(ip, &["-j", "-N", family, "rule", "show"])?,
                interface,
            )?;
        }
        selected.push(interface);
    }
    let ipv6 = selected.pop().flatten();
    let ipv4 = selected.pop().flatten();
    let interfaces = [ipv4.clone(), ipv6.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if interfaces.is_empty() {
        return Err(unavailable());
    }
    // DNS policy and encrypted resolver profiles remain owned by resolved.
    for interface in &interfaces {
        verify_index(interface)?;
    }
    Ok(Snapshot { ipv4, ipv6 })
}

#[cfg(target_os = "linux")]
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
        || socket.device()?.is_some()
    {
        return Err(invalid());
    }
    // A fresh socket needs no CAP_NET_RAW on upstream Linux >=5.7. Never
    // retry unbound if security policy or an inherited VRF rejects this call.
    socket.bind_device(Some(interface.name.as_bytes()))?;
    if socket.device()?.as_deref() != Some(interface.name.as_bytes()) {
        return Err(invalid());
    }
    verify_index(interface)
}

fn verify_index(interface: &Interface) -> io::Result<()> {
    valid_name(&interface.name)?;
    let name = CString::new(interface.name.as_str()).map_err(|_| invalid())?;
    if interface.index == 0 || unsafe { libc::if_nametoindex(name.as_ptr()) } != interface.index {
        return Err(unavailable());
    }
    Ok(())
}
fn executable(name: &str) -> io::Result<&'static str> {
    let paths = match name {
        "ip" => ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        "busctl" => [
            "/usr/bin/busctl",
            "/bin/busctl",
            "/usr/sbin/busctl",
            "/sbin/busctl",
        ],
        _ => return Err(invalid()),
    };
    paths
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or_else(unavailable)
}
fn parse_links(
    link_text: &str,
    address_text: &str,
    devices: &BTreeMap<String, String>,
) -> io::Result<BTreeMap<String, Interface>> {
    let addresses = rows(address_text)?;
    let mut result = BTreeMap::new();
    let mut indices = BTreeSet::new();
    for row in rows(link_text)? {
        let row = object(&row)?;
        let name = text(row, "ifname")?;
        valid_name(name)?;
        let Some(device) = devices.get(name) else {
            continue;
        };
        if row.get("link_type").and_then(Value::as_str) != Some("ether")
            || row.contains_key("linkinfo")
            || row.contains_key("master")
        {
            continue;
        }
        let flags = row
            .get("flags")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        if !flags.iter().any(|v| v == "UP")
            || !flags.iter().any(|v| v == "LOWER_UP")
            || flags.iter().any(|v| v == "LOOPBACK")
        {
            continue;
        }
        let index = number(row, "ifindex")?;
        if index == 0 || !indices.insert(index) {
            return Err(invalid());
        }
        let mac = text(row, "address")?;
        if mac.split(':').count() != 6
            || mac
                .split(':')
                .any(|v| v.len() != 2 || u8::from_str_radix(v, 16).is_err())
        {
            return Err(invalid());
        }
        let mut usable = Vec::new();
        for addrs in &addresses {
            let addrs = object(addrs)?;
            if text(addrs, "ifname")? != name {
                continue;
            }
            if number(addrs, "ifindex")? != index {
                return Err(invalid());
            }
            for addr in addrs
                .get("addr_info")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
            {
                let addr = object(addr)?;
                let family = text(addr, "family")?;
                if !matches!(family, "inet" | "inet6") {
                    continue;
                }
                if ["tentative", "dadfailed", "deprecated"]
                    .iter()
                    .any(|k| addr.get(*k) == Some(&Value::Bool(true)))
                    || addr.get("valid_life_time").and_then(Value::as_u64) == Some(0)
                {
                    continue;
                }
                let a = text(addr, "local")?
                    .parse::<IpAddr>()
                    .map_err(|_| invalid())?;
                if (family == "inet") != a.is_ipv4() || !valid_address(a) {
                    continue;
                }
                usable.push(a);
            }
        }
        usable.sort();
        usable.dedup();
        if usable.is_empty() {
            continue;
        }
        let interface = Interface {
            index,
            name: name.into(),
            identity: format!("linux:{index}:{name}:{mac}:{device}"),
            addresses: usable,
            gateway: None,
        };
        if result.insert(name.into(), interface).is_some() {
            return Err(invalid());
        }
    }
    Ok(result)
}
fn select_route(
    route_text: &str,
    links: &BTreeMap<String, Interface>,
    ipv6: bool,
) -> io::Result<Option<Interface>> {
    let mut candidates = Vec::new();
    for row in rows(route_text)? {
        let row = object(&row)?;
        if row
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| t != "unicast" && t != "local" && t != "broadcast")
            || ["nexthops", "nhid", "encap", "via"]
                .iter()
                .any(|k| row.contains_key(*k))
        {
            return Err(invalid());
        }
        let dev = text(row, "dev")?;
        let Some(interface) = links.get(dev) else {
            continue;
        };
        if text(row, "dst")? != "default" {
            continue;
        }
        if row
            .get("flags")
            .and_then(Value::as_array)
            .is_some_and(|f| f.iter().any(|v| v == "dead" || v == "linkdown"))
        {
            continue;
        }
        if !interface
            .addresses
            .iter()
            .any(|a| a.is_ipv6() == ipv6 && !is_link_local(*a))
        {
            continue;
        }
        let mut interface = interface.clone();
        if let Some(gateway) = row.get("gateway") {
            let gateway = gateway
                .as_str()
                .ok_or_else(invalid)?
                .parse::<IpAddr>()
                .map_err(|_| invalid())?;
            if gateway.is_ipv6() != ipv6 || !valid_address(gateway) {
                return Err(invalid());
            }
            interface.gateway = Some(gateway);
        }
        let metric = row
            .get("metric")
            .map(|v| v.as_u64().ok_or_else(invalid))
            .transpose()?
            .unwrap_or(0);
        candidates.push((metric, interface));
    }
    candidates.sort_by_key(|c| c.0);
    if candidates.get(1).is_some_and(|c| c.0 == candidates[0].0) {
        return Err(io::Error::other("physical_egress_ambiguous"));
    }
    Ok(candidates.into_iter().next().map(|c| c.1))
}
fn verify_rules(rule_text: &str, interface: &Interface) -> io::Result<()> {
    let mut seen = BTreeSet::new();
    let mut main = false;
    let mut marked = false;
    for row in rows(rule_text)? {
        let row = object(&row)?;
        let priority = number(row, "priority")?;
        if !seen.insert(priority) || text(row, "src")? != "all" {
            return Err(invalid());
        }
        if let Some(oif) = row.get("oif").and_then(Value::as_str) {
            // An ordinary non-inverted oif rule cannot match this bound socket.
            if oif != interface.name && !row.contains_key("not") && !row.contains_key("flags") {
                continue;
            }
            return Err(invalid());
        }
        match priority {
            0 | 32766 | 32767 => {
                only(row, &["priority", "src", "table", "protocol"])?;
                let expected = match priority {
                    0 => 255,
                    32766 => 254,
                    _ => 253,
                };
                if number(row, "table")? != expected {
                    return Err(invalid());
                }
            }
            31120 => {
                only(
                    row,
                    &[
                        "priority",
                        "src",
                        "table",
                        "protocol",
                        "suppress_prefixlength",
                    ],
                )?;
                if number(row, "table")? != 254 || number(row, "suppress_prefixlength")? != 0 {
                    return Err(invalid());
                }
                main = true;
            }
            31121 => {
                only(
                    row,
                    &[
                        "priority", "src", "table", "protocol", "not", "fwmark", "fwmask",
                    ],
                )?;
                let mark = row.get("fwmark").and_then(parse_mark).ok_or_else(invalid)?;
                if number(row, "table")? != 42761
                    || row.get("not") != Some(&Value::Bool(true))
                    || mark != 42761
                    || row
                        .get("fwmask")
                        .is_some_and(|v| parse_mark(v) != Some(u32::MAX))
                {
                    return Err(invalid());
                }
                marked = true;
            }
            _ => return Err(invalid()),
        }
    }
    if !seen.contains(&0) || !seen.contains(&32766) || main != marked {
        return Err(invalid());
    }
    Ok(())
}
/// DNS uses our bound sockets: resolved's scoped TCP/DoT path can remain
/// unbound. Read metadata only and reject policies we cannot preserve.
#[cfg(target_os = "linux")]
pub(super) fn dns_servers(snapshot: &Snapshot) -> io::Result<Vec<DnsServer>> {
    let interface = match (&snapshot.ipv4, &snapshot.ipv6) {
        (Some(interface), None) | (None, Some(interface)) => interface,
        _ => return Err(invalid()),
    };
    verify_index(interface)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(7);
    let run = |program: &str, args: &[&str]| {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "physical_dns_metadata_timeout",
            ));
        }
        command::run_with_timeout(
            program,
            args,
            remaining.min(std::time::Duration::from_secs(2)),
        )
    };
    let local = local_addresses(&run(executable("ip")?, &["-j", "addr", "show"])?)?;
    if interface
        .addresses
        .iter()
        .any(|address| !local.contains(address))
    {
        return Err(invalid());
    }
    let busctl = executable("busctl")?;
    let servers = dns::servers(interface, &local, |args| run(busctl, args))?;
    verify_index(interface)?;
    Ok(servers)
}

fn local_addresses(raw: &str) -> io::Result<Vec<IpAddr>> {
    let mut result = BTreeSet::new();
    for row in rows(raw)? {
        let values = object(&row)?
            .get("addr_info")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        for value in values {
            let value = object(value)?;
            let family = text(value, "family")?;
            if !matches!(family, "inet" | "inet6") {
                continue;
            }
            let address: IpAddr = text(value, "local")?.parse().map_err(|_| invalid())?;
            if (family == "inet") != address.is_ipv4() {
                return Err(invalid());
            }
            result.insert(address);
        }
    }
    if result.is_empty() {
        return Err(invalid());
    }
    Ok(result.into_iter().collect())
}

fn rows(text: &str) -> io::Result<Vec<Value>> {
    let v: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    let rows = v.as_array().ok_or_else(invalid)?;
    if rows.len() > 16384 {
        return Err(invalid());
    }
    Ok(rows.clone())
}
fn object(v: &Value) -> io::Result<&Map<String, Value>> {
    v.as_object().ok_or_else(invalid)
}
fn text<'a>(v: &'a Map<String, Value>, key: &str) -> io::Result<&'a str> {
    v.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(v: &Map<String, Value>, key: &str) -> io::Result<u32> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(invalid)
}
fn only(v: &Map<String, Value>, keys: &[&str]) -> io::Result<()> {
    if v.keys().any(|k| !keys.contains(&k.as_str())) {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn parse_mark(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|v| u32::try_from(v).ok()).or_else(|| {
        let s = v.as_str()?;
        if let Some(s) = s.strip_prefix("0x") {
            u32::from_str_radix(s, 16).ok()
        } else {
            s.parse().ok()
        }
    })
}
fn valid_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"_.:-".contains(&b)))
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn valid_address(a: IpAddr) -> bool {
    !matches!(a, IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
        && !a.is_unspecified()
        && !a.is_loopback()
        && !a.is_multicast()
        && a != IpAddr::V4(Ipv4Addr::BROADCAST)
}
fn is_link_local(a: IpAddr) -> bool {
    matches!(a,IpAddr::V6(v) if v.is_unicast_link_local())
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "physical_network_state_invalid")
}
fn unavailable() -> io::Error {
    io::Error::other("physical_egress_unavailable")
}

#[cfg(all(test, target_os = "linux"))]
mod native_tests {
    use super::*;
    #[test]
    fn native_fresh_socket_can_bind_once_and_read_back() {
        let name = CString::new("lo").unwrap();
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(index, 0);
        let interface = Interface {
            index,
            name: "lo".into(),
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
            assert_eq!(socket.device().unwrap().as_deref(), Some(b"lo".as_slice()));
            assert!(bind_socket(&socket, &interface, remote).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LINKS: &str = r#"[{"ifindex":2,"ifname":"eth0","flags":["UP","LOWER_UP"],"link_type":"ether","address":"00:11:22:33:44:55"},{"ifindex":9,"ifname":"wg0","flags":["UP","LOWER_UP"],"link_type":"none","linkinfo":{"info_kind":"wireguard"}}]"#;
    const ADDRS: &str = r#"[{"ifindex":2,"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.4","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8::4","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::4","prefixlen":64,"scope":"link"}]}]"#;
    fn links() -> BTreeMap<String, Interface> {
        parse_links(
            LINKS,
            ADDRS,
            &BTreeMap::from([("eth0".into(), "/sys/devices/pci/eth0".into())]),
        )
        .unwrap()
    }
    #[test]
    fn physical_route_ignores_vpn_and_supports_both_families() {
        let links = links();
        let v4=select_route(r#"[{"dst":"default","dev":"wg0","metric":0},{"dst":"default","dev":"eth0","gateway":"192.0.2.1","metric":100}]"#,&links,false).unwrap().unwrap();
        assert_eq!(
            (v4.index, v4.gateway),
            (2, Some("192.0.2.1".parse().unwrap()))
        );
        let v6 = select_route(
            r#"[{"dst":"default","dev":"eth0","gateway":"fe80::1","metric":1024}]"#,
            &links,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(v6.gateway, Some("fe80::1".parse().unwrap()));
        assert!(v6.addresses.contains(&"2001:db8::4".parse().unwrap()));
    }
    #[test]
    fn equal_cost_defaults_are_rejected() {
        assert!(select_route(r#"[{"dst":"default","dev":"eth0","gateway":"192.0.2.1","metric":100},{"dst":"default","dev":"eth0","gateway":"192.0.2.2","metric":100}]"#,&links(),false).is_err());
    }
    #[test]
    fn policy_blocks_and_multipath_are_not_ignored() {
        for routes in [
            r#"[{"type":"blackhole","dst":"203.0.113.0/24"},{"dst":"default","dev":"eth0"}]"#,
            r#"[{"dst":"default","nexthops":[{"dev":"eth0"}]}]"#,
        ] {
            assert!(select_route(routes, &links(), false).is_err());
        }
    }
    #[test]
    fn physical_identity_requires_hardware_up_and_usable_addresses() {
        assert!(parse_links(LINKS, ADDRS, &BTreeMap::new())
            .unwrap()
            .is_empty());
        assert!(parse_links(
            &LINKS.replace("LOWER_UP", "DOWN"),
            ADDRS,
            &BTreeMap::from([("eth0".into(), "pci".into())])
        )
        .unwrap()
        .is_empty());
    }
    #[test]
    fn accepts_only_known_ordinary_fwmark_and_nonmatching_bound_rules() {
        let rules = r#"[{"priority":0,"src":"all","table":255},{"priority":12001,"src":"all","table":52001,"oif":"nlm-wga","protocol":4},{"priority":31120,"src":"all","table":254,"suppress_prefixlength":0},{"priority":31121,"src":"all","table":42761,"not":true,"fwmark":"0xa709"},{"priority":32766,"src":"all","table":254},{"priority":32767,"src":"all","table":253}]"#;
        verify_rules(rules, links().get("eth0").unwrap()).unwrap();
        assert!(verify_rules(
            &rules.replace("0xa709", "0x42"),
            links().get("eth0").unwrap()
        )
        .is_err());
        assert!(verify_rules(
            &rules.replace("nlm-wga", "eth0"),
            links().get("eth0").unwrap()
        )
        .is_err());
    }

    #[test]
    fn dns_guard_local_addresses_include_vpn_and_down_interfaces() {
        let input = r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.4"}]},{"ifname":"wg0","addr_info":[{"family":"inet","local":"10.241.0.1"}]},{"ifname":"down0","addr_info":[{"family":"inet6","local":"2001:db8::53"}]}]"#;
        let values = local_addresses(input).unwrap();
        for address in ["192.0.2.4", "10.241.0.1", "2001:db8::53"] {
            assert!(values.contains(&address.parse().unwrap()));
        }
        assert!(local_addresses("[]").is_err());
        assert!(
            local_addresses(r#"[{"addr_info":[{"family":"inet6","local":"192.0.2.4"}]}]"#).is_err()
        );
    }
}
