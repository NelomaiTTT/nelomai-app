use super::{OwnedRoute, RouteBackend, RouteScope};
use crate::process::{output_with_timeout, COMMAND_TIMEOUT};
use crate::ServiceError;
#[cfg(target_os = "linux")]
use defguard_wireguard_rs::peer::Peer;
use ipnet::{IpNet, Ipv4Net};
use nelomai_client_tunnel::redundancy::route_plan::tunnel_destinations_preserving;
#[cfg(target_os = "linux")]
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const AWG_ROUTE_STATE_FILE: &str = "awg-routes-state.json";
const AWG_ROUTE_STATE_FORMAT: u16 = 1;
const AWG_ROUTE_STATE_MAX_SIZE: u64 = 64 * 1024;
const AWG_FWMARK_TABLE: u32 = 42_761;
const AWG_MAIN_RULE_PRIORITY: u32 = 31_120;
const AWG_TUNNEL_RULE_PRIORITY: u32 = 31_121;

#[derive(Clone)]
pub(crate) struct LinuxEgress {
    interface: String,
    gateway: Option<String>,
    source: Option<String>,
}

pub(crate) struct SystemRouteBackend {
    ip: PathBuf,
}

impl SystemRouteBackend {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        Ok(Self { ip: ip_command()? })
    }
}

pub(crate) fn ip_command() -> Result<PathBuf, ServiceError> {
    ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| ServiceError::Backend("ip_command_unavailable".to_string()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RouteFamily {
    Ipv4,
    Ipv6,
}

impl RouteFamily {
    fn ip_argument(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct UserspaceRoute {
    family: RouteFamily,
    destination: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct UserspaceRouteState {
    format_version: u16,
    interface_name: String,
    default_families: Vec<RouteFamily>,
    routes: Vec<UserspaceRoute>,
}

pub(crate) struct LinuxOrdinaryRoutes {
    ip: PathBuf,
    state_path: PathBuf,
    state: Option<UserspaceRouteState>,
}

impl LinuxOrdinaryRoutes {
    pub(crate) fn new(runtime_directory: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let state_path = runtime_directory.as_ref().join(AWG_ROUTE_STATE_FILE);
        let state = load_userspace_route_state(&state_path)?;
        Ok(Self {
            ip: ip_command()?,
            state_path,
            state,
        })
    }

    /// Old AWG journals were written before route/rule creation. Even an
    /// exact live value could have been installed independently after a crash.
    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let Some(state) = &self.state else {
            return Ok(());
        };
        for route in &state.routes {
            let text = query_ip(
                &self.ip,
                &[
                    route.family.ip_argument(),
                    "route",
                    "show",
                    "exact",
                    &route.destination,
                ],
            )?;
            if text.lines().any(|line| {
                let tokens: Vec<_> = line.split_whitespace().collect();
                value_after(&tokens, "dev") == Some(&state.interface_name)
                    && value_after(&tokens, "proto") == Some("static")
            }) {
                return Err(ServiceError::Backend(
                    "legacy_route_ownership_unconfirmed".into(),
                ));
            }
        }
        for family in &state.default_families {
            for priority in [AWG_MAIN_RULE_PRIORITY, AWG_TUNNEL_RULE_PRIORITY] {
                let output = query_ip(
                    &self.ip,
                    &[
                        family.ip_argument(),
                        "rule",
                        "show",
                        "priority",
                        &priority.to_string(),
                    ],
                )?;
                if userspace_rule_is_owned(&output, priority) {
                    return Err(ServiceError::Backend(
                        "legacy_route_ownership_unconfirmed".into(),
                    ));
                }
            }
            let output = query_ip(
                &self.ip,
                &[
                    family.ip_argument(),
                    "route",
                    "show",
                    "table",
                    &AWG_FWMARK_TABLE.to_string(),
                ],
            )?;
            if output.lines().any(|line| {
                let tokens: Vec<_> = line.split_whitespace().collect();
                tokens.first() == Some(&"default")
                    && value_after(&tokens, "dev") == Some(&state.interface_name)
            }) {
                return Err(ServiceError::Backend(
                    "legacy_route_ownership_unconfirmed".into(),
                ));
            }
        }
        remove_userspace_route_state(&self.state_path)?;
        self.state = None;
        Ok(())
    }

    pub(crate) fn has_routes(&self) -> bool {
        self.state.is_some()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn apply(
        &self,
        index: u32,
        interface: &str,
        peers: &[Peer],
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        let policy = Ipv4RoutePlan::from_options(options)
            .map_err(|error| ServiceError::Backend(error.stable_code().into()))?;
        let endpoints: HashSet<_> = peers
            .iter()
            .map(|peer| {
                peer.endpoint
                    .map(|a| a.ip())
                    .ok_or(ServiceError::InvalidConfiguration)
            })
            .collect::<Result<_, _>>()?;
        let mut holes: Vec<_> = policy
            .excluded_networks
            .into_iter()
            .map(IpNet::V4)
            .collect();
        holes.extend(endpoints.iter().copied().map(IpNet::from));
        let allowed = peers
            .iter()
            .flat_map(|peer| &peer.allowed_ips)
            .map(|net| {
                IpNet::new(net.address, net.cidr)
                    .map(|net| net.trunc())
                    .map_err(|_| ServiceError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut network = crate::member_network::linux::LinuxNetwork::new(
            crate::member_network::linux::NativeLinuxCommands::new()
                .map_err(|_| invalid_table())?,
            [],
        )
        .map_err(|_| invalid_table())?;
        let mut read_routes = || -> Result<(Vec<MainRoute>, HashSet<String>), ServiceError> {
            let local_interfaces = if policy.exclude_local_networks {
                network
                    .physical_links()
                    .map_err(|_| invalid_table())?
                    .into_keys()
                    .collect()
            } else {
                HashSet::new()
            };
            let mut routes = Vec::new();
            for family in [RouteFamily::Ipv4, RouteFamily::Ipv6] {
                if !allowed
                    .iter()
                    .any(|net| net.addr().is_ipv4() == (family == RouteFamily::Ipv4))
                {
                    continue;
                }
                // A higher-priority policy table could defeat all of our data
                // routes while the main-table readback still looks correct.
                network
                    .verify_main_rules(family == RouteFamily::Ipv6)
                    .map_err(|_| invalid_table())?;
                let rows = query_ip(
                    &self.ip,
                    &["-j", family.ip_argument(), "route", "show", "table", "main"],
                )?;
                routes.extend(parse_main_routes(&rows, family)?);
            }
            Ok((routes, local_interfaces))
        };
        let (main, local_interfaces) = read_routes()?;
        let destinations =
            ordinary_destinations(&allowed, &holes, &main, interface, &local_interfaces)?;
        let egress = |endpoint: &IpAddr| -> Result<(String, Option<IpAddr>), ServiceError> {
            let family = if endpoint.is_ipv4() { "-4" } else { "-6" };
            let text = query_ip(
                &self.ip,
                &["-j", family, "route", "get", &endpoint.to_string()],
            )?;
            let rows: Vec<serde_json::Value> =
                serde_json::from_str(&text).map_err(|_| invalid_table())?;
            let [row] = rows.as_slice() else {
                return Err(invalid_table());
            };
            let name = row["dev"]
                .as_str()
                .filter(|s| !s.is_empty() && *s != interface)
                .ok_or_else(invalid_table)?;
            let gateway = row
                .get("gateway")
                .map(|v| {
                    v.as_str()
                        .and_then(|ip| ip.parse().ok())
                        .ok_or_else(invalid_table)
                })
                .transpose()?;
            Ok((name.into(), gateway))
        };
        let paths: Vec<_> = endpoints
            .iter()
            .map(|ip| egress(ip).map(|path| (ip, path)))
            .collect::<Result<_, _>>()?;
        let mut socket = native::RoutingSocket::new()?;
        for &destination in &destinations {
            socket.add(index, destination)?;
        }
        // A foreign route with another metric can coexist even after an
        // exclusive netlink add. Verify the whole plan in two family dumps.
        let expected: HashSet<_> = destinations.iter().copied().collect();
        let mut confirmed = HashSet::new();
        let mut others = Vec::new();
        let (current_main, local_interfaces) = read_routes()?;
        for row in current_main {
            if expected.contains(&row.net) {
                if row.device.as_deref() != Some(interface)
                    || !row.static_direct
                    || !confirmed.insert(row.net)
                {
                    return Err(route_conflict());
                }
            } else {
                others.push(row);
            }
        }
        if confirmed != expected
            || ordinary_destinations(&allowed, &holes, &others, interface, &local_interfaces)?
                != destinations
        {
            return Err(route_conflict());
        }
        for (ip, path) in paths {
            if egress(ip)? != path {
                return Err(ServiceError::Backend(
                    "ordinary_endpoint_route_changed".into(),
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn create_wireguard_link(name: &str, group: u32) -> Result<(), ServiceError> {
        native::RoutingSocket::new()?.create_wireguard_link(name, group)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn set_link_group(index: u32, group: u32) -> Result<(), ServiceError> {
        native::RoutingSocket::new()?.set_link_group(index, group)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn delete_link(index: u32) -> Result<(), ServiceError> {
        native::RoutingSocket::new()?.delete_link(index)
    }
}

fn invalid_table() -> ServiceError {
    ServiceError::Backend("route_table_unavailable".into())
}

fn route_conflict() -> ServiceError {
    ServiceError::Backend("route_conflict".into())
}

struct MainRoute {
    net: IpNet,
    device: Option<String>,
    connected: bool,
    static_direct: bool,
}

fn parse_main_routes(text: &str, family: RouteFamily) -> Result<Vec<MainRoute>, ServiceError> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(text).map_err(|_| invalid_table())?;
    let mut routes = Vec::new();
    for row in rows {
        let dst = row["dst"].as_str().ok_or_else(invalid_table)?;
        if dst == "default" {
            continue;
        }
        let net = dst
            .parse::<IpNet>()
            .or_else(|_| dst.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| invalid_table())?;
        if net.addr().is_ipv4() != (family == RouteFamily::Ipv4) || net.trunc() != net {
            return Err(invalid_table());
        }
        let direct = row.get("gateway").is_none()
            && row.get("via").is_none()
            && row.get("nexthops").is_none();
        routes.push(MainRoute {
            net,
            device: row["dev"].as_str().map(str::to_owned),
            connected: direct && (row["scope"] == "link" || row["protocol"] == "kernel"),
            static_direct: direct && row["protocol"] == "static",
        });
    }
    Ok(routes)
}

fn ordinary_destinations(
    allowed: &[IpNet],
    excluded: &[IpNet],
    routes: &[MainRoute],
    interface: &str,
    local_interfaces: &HashSet<String>,
) -> Result<Vec<IpNet>, ServiceError> {
    let mut holes = excluded.to_vec();
    let mut tunnel_connected = Vec::new();
    let full4 = allowed
        .iter()
        .any(|n| n.addr().is_ipv4() && n.prefix_len() == 0);
    let full6 = allowed
        .iter()
        .any(|n| n.addr().is_ipv6() && n.prefix_len() == 0);
    for row in routes {
        if row.device.as_deref() == Some(interface) {
            tunnel_connected.push(row.net);
        } else if (row.net.prefix_len() == 1
            && if row.net.addr().is_ipv4() {
                full4
            } else {
                full6
            })
            || (row.connected
                && row
                    .device
                    .as_ref()
                    .is_some_and(|name| local_interfaces.contains(name)))
        {
            holes.push(row.net);
        }
    }
    // Interface address assignment itself can create a connected tunnel
    // route. An overlap with a physical exclusion cannot be fixed by omitting
    // a data route; abort and let teardown remove the new tunnel link.
    if tunnel_connected.iter().any(|n| {
        holes
            .iter()
            .any(|hole| hole.contains(n) || n.contains(hole))
    }) {
        return Err(route_conflict());
    }
    holes.extend(tunnel_connected);
    let existing: Vec<_> = routes.iter().map(|r| r.net).collect();
    let planned = tunnel_destinations_preserving(allowed, &holes, &existing)
        .map_err(|e| ServiceError::Backend(e.to_string()))?;
    let present: HashSet<_> = existing.into_iter().collect();
    if planned.iter().any(|n| present.contains(n)) {
        return Err(route_conflict());
    }
    Ok(planned)
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
    };
    use netlink_packet_route::{
        link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType},
        AddressFamily, RouteNetlinkMessage,
    };
    use netlink_sys::{constants::NETLINK_ROUTE, Socket, SocketAddr};
    use std::os::fd::AsRawFd;

    pub(super) struct RoutingSocket {
        socket: Socket,
        sequence: u32,
    }
    impl RoutingSocket {
        pub(super) fn new() -> Result<Self, ServiceError> {
            let socket = Socket::new(NETLINK_ROUTE).map_err(|_| invalid_table())?;
            socket
                .connect(&SocketAddr::new(0, 0))
                .map_err(|_| invalid_table())?;
            let timeout = libc::timeval {
                tv_sec: 3,
                tv_usec: 0,
            };
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&timeout as *const libc::timeval).cast(),
                    std::mem::size_of_val(&timeout) as _,
                )
            } != 0
            {
                return Err(invalid_table());
            }
            Ok(Self {
                socket,
                sequence: 0,
            })
        }
        pub(super) fn add(&mut self, index: u32, net: IpNet) -> Result<(), ServiceError> {
            if index == 0 || net.prefix_len() == 0 {
                return Err(invalid_table());
            }
            let mut route = RouteMessage::default();
            route.header.address_family = if net.addr().is_ipv4() {
                AddressFamily::Inet
            } else {
                AddressFamily::Inet6
            };
            route.header.destination_prefix_length = net.prefix_len();
            route.header.table = 254;
            route.header.scope = RouteScope::Link;
            route.header.kind = RouteType::Unicast;
            route.header.protocol = RouteProtocol::Static;
            let dst = match net.network() {
                IpAddr::V4(ip) => RouteAddress::Inet(ip),
                IpAddr::V6(ip) => RouteAddress::Inet6(ip),
            };
            route.attributes = vec![RouteAttribute::Oif(index), RouteAttribute::Destination(dst)];
            self.request(
                RouteNetlinkMessage::NewRoute(route),
                NLM_F_CREATE | NLM_F_EXCL,
            )
        }
        pub(super) fn create_wireguard_link(
            &mut self,
            name: &str,
            group: u32,
        ) -> Result<(), ServiceError> {
            let mut link = LinkMessage::default();
            link.header.flags = LinkFlags::Up;
            link.header.change_mask = LinkFlags::Up;
            link.attributes = vec![
                LinkAttribute::IfName(name.into()),
                LinkAttribute::Group(group),
                LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Wireguard)]),
            ];
            self.request(
                RouteNetlinkMessage::NewLink(link),
                NLM_F_CREATE | NLM_F_EXCL,
            )
        }
        pub(super) fn set_link_group(
            &mut self,
            index: u32,
            group: u32,
        ) -> Result<(), ServiceError> {
            if index == 0 {
                return Err(invalid_table());
            }
            let mut link = LinkMessage::default();
            link.header.index = index;
            link.attributes = vec![LinkAttribute::Group(group)];
            self.request(RouteNetlinkMessage::NewLink(link), 0)
        }
        pub(super) fn delete_link(&mut self, index: u32) -> Result<(), ServiceError> {
            if index == 0 {
                return Err(invalid_table());
            }
            let mut link = LinkMessage::default();
            link.header.index = index;
            self.request(RouteNetlinkMessage::DelLink(link), 0)
        }
        fn request(&mut self, msg: RouteNetlinkMessage, flags: u16) -> Result<(), ServiceError> {
            self.sequence += 1;
            let mut req = NetlinkMessage::from(msg);
            req.header.sequence_number = self.sequence;
            req.header.flags = flags | NLM_F_REQUEST | NLM_F_ACK;
            req.finalize();
            let mut bytes = vec![0; req.buffer_len()];
            req.serialize(&mut bytes);
            if self.socket.send(&bytes, 0).map_err(|_| invalid_table())? != bytes.len() {
                return Err(invalid_table());
            }
            let mut buf = [0u8; 8192];
            let (n, sender) = self
                .socket
                .recv_from(&mut &mut buf[..], 0)
                .map_err(|_| invalid_table())?;
            if n >= buf.len() || sender.port_number() != 0 || sender.multicast_groups() != 0 {
                return Err(invalid_table());
            }
            let ack = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&buf[..n])
                .map_err(|_| invalid_table())?;
            if ack.header.sequence_number != self.sequence {
                return Err(invalid_table());
            }
            match ack.payload {
                NetlinkPayload::Error(e) if e.code.is_none() => Ok(()),
                _ => Err(ServiceError::Backend(
                    "ordinary_route_change_rejected".into(),
                )),
            }
        }
    }
}

fn query_ip(ip: &Path, arguments: &[&str]) -> Result<String, ServiceError> {
    let output = output_with_timeout(
        Command::new(ip)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if !output.status.success() {
        // A FIB table is created lazily. Before the first AWG start (or after
        // cleanup), iproute2 reports its absence with exit 2, not empty success.
        // Only accept this exact read-only query/result; fail closed otherwise.
        let missing_table_message = match arguments {
            ["-4", "route", "show", "table", "42761"] => {
                "Error: ipv4: FIB table does not exist.\nDump terminated"
            }
            ["-6", "route", "show", "table", "42761"] => {
                "Error: ipv6: FIB table does not exist.\nDump terminated"
            }
            _ => "",
        };
        if output.status.code() != Some(2)
            || !output.stdout.is_empty()
            || missing_table_message.is_empty()
            || String::from_utf8_lossy(&output.stderr).trim() != missing_table_message
        {
            return Err(ServiceError::Backend("route_command_failed".to_string()));
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn userspace_rule_is_owned(output: &str, priority: u32) -> bool {
    let expected_priority = priority.to_string();
    let expected_table = AWG_FWMARK_TABLE.to_string();
    output.lines().any(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>();
        if normalized
            .first()
            .is_none_or(|value| value.trim_end_matches(':') != expected_priority)
        {
            return false;
        }
        match priority {
            AWG_MAIN_RULE_PRIORITY => {
                (value_after(&normalized, "lookup") == Some("main")
                    || value_after(&normalized, "table") == Some("main"))
                    && value_after(&normalized, "suppress_prefixlength") == Some("0")
            }
            AWG_TUNNEL_RULE_PRIORITY => {
                normalized.contains(&"not")
                    && value_after(&normalized, "fwmark").and_then(parse_fwmark)
                        == Some(AWG_FWMARK_TABLE)
                    && (value_after(&normalized, "lookup") == Some(expected_table.as_str())
                        || value_after(&normalized, "table") == Some(expected_table.as_str()))
            }
            _ => false,
        }
    })
}

fn parse_fwmark(value: &str) -> Option<u32> {
    let value = value.split('/').next()?;
    value
        .strip_prefix("0x")
        .map(|value| u32::from_str_radix(value, 16).ok())
        .unwrap_or_else(|| value.parse().ok())
}

fn load_userspace_route_state(path: &Path) -> Result<Option<UserspaceRouteState>, ServiceError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ServiceError::Backend("route_state_read_failed".to_string())),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > AWG_ROUTE_STATE_MAX_SIZE
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    let bytes =
        fs::read(path).map_err(|_| ServiceError::Backend("route_state_read_failed".to_string()))?;
    let state: UserspaceRouteState = serde_json::from_slice(&bytes)
        .map_err(|_| ServiceError::Backend("route_state_invalid".to_string()))?;
    validate_userspace_route_state(&state)?;
    Ok(Some(state))
}

fn validate_userspace_route_state(state: &UserspaceRouteState) -> Result<(), ServiceError> {
    if state.format_version != AWG_ROUTE_STATE_FORMAT
        || state.interface_name.is_empty()
        || state.interface_name.chars().any(char::is_whitespace)
        || state.default_families.len() > 2
        || state.routes.len() > 1024
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    let mut families = HashSet::new();
    if state
        .default_families
        .iter()
        .any(|family| !families.insert(*family))
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    for route in &state.routes {
        let network = route
            .destination
            .parse::<IpNet>()
            .map_err(|_| ServiceError::Backend("route_state_invalid".to_string()))?;
        if network.to_string() != route.destination
            || network.addr().is_ipv4() != (route.family == RouteFamily::Ipv4)
        {
            return Err(ServiceError::Backend("route_state_invalid".to_string()));
        }
    }
    Ok(())
}

fn remove_userspace_route_state(path: &Path) -> Result<(), ServiceError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ServiceError::Backend(
            "route_state_remove_failed".to_string(),
        )),
    }
}

impl RouteBackend for SystemRouteBackend {
    type Egress = LinuxEgress;

    fn discover_egress(&self) -> Result<Self::Egress, ServiceError> {
        parse_default_route(&run(&self.ip, &["-4", "route", "show", "default"])?.stdout)
            .ok_or_else(|| ServiceError::Backend("physical_egress_unavailable".to_string()))
    }

    fn local_networks(&self, egress: &Self::Egress) -> Result<Vec<Ipv4Net>, ServiceError> {
        Ok(parse_local_networks(
            &run(
                &self.ip,
                &[
                    "-o",
                    "-4",
                    "addr",
                    "show",
                    "dev",
                    &egress.interface,
                    "scope",
                    "global",
                ],
            )?
            .stdout,
        ))
    }

    fn fingerprint_material(&self, egress: &Self::Egress, local_networks: &[Ipv4Net]) -> String {
        let networks = local_networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "linux\0{}\0{}\0{}\0{}",
            egress.interface,
            egress.gateway.as_deref().unwrap_or_default(),
            egress.source.as_deref().unwrap_or_default(),
            networks
        )
    }

    fn route_presence(
        &self,
        routes: &[OwnedRoute],
    ) -> Result<Vec<Option<RouteScope>>, ServiceError> {
        let output = run(&self.ip, &["-4", "route", "show", "table", "main"])?;
        let output = String::from_utf8_lossy(&output.stdout);
        let table = output
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        routes
            .iter()
            .map(|route| {
                validate_owned_route(route)?;
                Ok(table
                    .iter()
                    .any(|tokens| route_matches_tokens(tokens, route))
                    .then_some(RouteScope::Unscoped))
            })
            .collect()
    }
}

fn validate_owned_route(route: &OwnedRoute) -> Result<(), ServiceError> {
    route
        .destination
        .parse::<Ipv4Net>()
        .ok()
        .filter(|network| network.to_string() == route.destination)
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    if route
        .gateway
        .as_deref()
        .is_some_and(|gateway| gateway.parse::<std::net::Ipv4Addr>().is_err())
    {
        return Err(ServiceError::Backend("route_state_invalid".to_string()));
    }
    route
        .metric
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?;
    Ok(())
}

fn route_matches_tokens(tokens: &[&str], route: &OwnedRoute) -> bool {
    let Some(expected_metric) = route.metric else {
        return false;
    };
    let Ok(expected_destination) = route.destination.parse::<Ipv4Net>() else {
        return false;
    };
    // iproute2 omits /32 when rendering a host route. Compare the network,
    // retaining every ownership check before cleanup may remove the route.
    let destination = tokens.first().and_then(|value| {
        value.parse::<Ipv4Net>().ok().or_else(|| {
            value
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .and_then(|address| Ipv4Net::new(address, 32).ok())
        })
    });
    destination == Some(expected_destination)
        && value_after(tokens, "via") == route.gateway.as_deref()
        && value_after(tokens, "dev") == Some(route.interface_identifier.as_str())
        && value_after(tokens, "metric").and_then(|value| value.parse::<u32>().ok())
            == Some(expected_metric)
        && value_after(tokens, "proto") == Some("static")
}

fn run(path: &Path, arguments: &[&str]) -> Result<Output, ServiceError> {
    let output = output_with_timeout(
        Command::new(path)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ServiceError::Backend("route_command_failed".to_string()))
    }
}

fn parse_default_route(output: &[u8]) -> Option<LinuxEgress> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            if tokens.first() != Some(&"default") {
                return None;
            }
            let interface = value_after(&tokens, "dev")?;
            if virtual_interface(interface) {
                return None;
            }
            let metric = value_after(&tokens, "metric")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default();
            let source = value_after(&tokens, "src").map(str::to_string);
            Some((
                metric,
                LinuxEgress {
                    interface: interface.to_string(),
                    gateway: value_after(&tokens, "via").map(str::to_string),
                    source,
                },
            ))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, egress)| egress)
}

fn parse_local_networks(output: &[u8]) -> Vec<Ipv4Net> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            let network = value_after(&tokens, "inet")?.parse::<Ipv4Net>().ok()?;
            Ipv4Net::new(network.network(), network.prefix_len()).ok()
        })
        .collect()
}

fn value_after<'a>(tokens: &'a [&str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|token| *token == key)
        .and_then(|index| tokens.get(index + 1).copied())
}

fn virtual_interface(value: &str) -> bool {
    [
        "nlm-wg",
        "wg",
        "tun",
        "tap",
        "veth",
        "docker",
        "br-",
        "tailscale",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        || value == "lo"
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ordinary_dual_stack_routes_keep_existing_static_and_connected_paths() {
        let mut main=parse_main_routes(r#"[{"dst":"default","dev":"eth0"},{"dst":"10.42.0.0/16","dev":"eth0","scope":"link","protocol":"kernel"},{"dst":"203.0.113.0/24","dev":"eth0","gateway":"192.0.2.2","protocol":"static"}]"#,RouteFamily::Ipv4).unwrap();
        main.extend(
            parse_main_routes(
                r#"[{"dst":"2001:db8::/48","dev":"eth0","gateway":"fd00::1","protocol":"static"}]"#,
                RouteFamily::Ipv6,
            )
            .unwrap(),
        );
        let allowed = ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let holes = [
            "203.0.113.7/32".parse().unwrap(),
            "198.51.100.10/32".parse().unwrap(),
            "2001:db8::a/128".parse().unwrap(),
        ];
        let data = ordinary_destinations(
            &allowed,
            &holes,
            &main,
            "nlm-wg0",
            &HashSet::from(["eth0".into()]),
        )
        .unwrap();
        let tunneled = |s: &str| {
            data.iter()
                .any(|n| n.contains(&s.parse::<IpAddr>().unwrap()))
        };
        for bypass in ["10.42.1.1", "203.0.113.6", "198.51.100.10", "2001:db8::b"] {
            assert!(!tunneled(bypass), "{bypass}");
        }
        assert!(tunneled("198.51.100.11"));
        assert!(tunneled("2001:db8:1::b"));
    }

    #[test]
    fn ordinary_specific_route_refuses_a_foreign_equal_prefix_at_any_metric() {
        let main = parse_main_routes(
            r#"[{"dst":"203.0.113.0/24","dev":"eth0","gateway":"192.0.2.1","metric":900}]"#,
            RouteFamily::Ipv4,
        )
        .unwrap();
        assert!(ordinary_destinations(
            &["203.0.113.0/24".parse().unwrap()],
            &[],
            &main,
            "nlm-awg0",
            &HashSet::new()
        )
        .is_err());
    }

    #[test]
    fn ordinary_exclusion_inside_tunnel_connected_prefix_is_unavailable() {
        let main = parse_main_routes(
            r#"[{"dst":"10.2.0.0/24","dev":"nlm-wg0","protocol":"kernel"}]"#,
            RouteFamily::Ipv4,
        )
        .unwrap();
        assert!(ordinary_destinations(
            &["0.0.0.0/0".parse().unwrap()],
            &["10.2.0.19/32".parse().unwrap()],
            &main,
            "nlm-wg0",
            &HashSet::new()
        )
        .is_err());
    }

    #[test]
    fn ordinary_does_not_treat_another_vpn_as_a_physical_lan() {
        let main = parse_main_routes(
            r#"[{"dst":"10.0.0.0/8","dev":"wg-other","scope":"link","protocol":"kernel"}]"#,
            RouteFamily::Ipv4,
        )
        .unwrap();
        let allowed = ["10.20.0.0/16".parse().unwrap()];
        assert_eq!(
            ordinary_destinations(
                &allowed,
                &[],
                &main,
                "nlm-wg0",
                &HashSet::from(["eth0".into()])
            )
            .unwrap(),
            allowed
        );
    }

    #[test]
    fn legacy_exact_replacement_never_grants_route_delete_authority() {
        let dir = tempfile::tempdir().unwrap();
        let ip = dir.path().join("ip");
        let calls = dir.path().join("calls");
        fs::write(&ip, format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$*\" in *show*) echo '192.0.2.0/24 dev nlm-awg0 proto static';; esac\n", calls.display())).unwrap();
        fs::set_permissions(&ip, fs::Permissions::from_mode(0o700)).unwrap();
        let state = UserspaceRouteState {
            format_version: 1,
            interface_name: "nlm-awg0".into(),
            default_families: vec![],
            routes: vec![UserspaceRoute {
                family: RouteFamily::Ipv4,
                destination: "192.0.2.0/24".into(),
            }],
        };
        let mut manager = LinuxOrdinaryRoutes {
            ip,
            state_path: dir.path().join("state"),
            state: Some(state),
        };
        assert!(manager.cleanup().is_err());
        assert!(!fs::read_to_string(calls).unwrap().contains("route del"));
    }
    #[test]
    fn host_route_without_printed_prefix_is_recognized_for_cleanup() {
        let route = OwnedRoute {
            destination: "91.221.164.24/32".into(),
            interface_identifier: "wlan0".into(),
            gateway: Some("10.60.26.17".into()),
            metric: Some(42760),
        };
        for destination in ["91.221.164.24", "91.221.164.24/32"] {
            let line = format!("{destination} via 10.60.26.17 dev wlan0 proto static metric 42760");
            assert!(route_matches_tokens(
                &line.split_whitespace().collect::<Vec<_>>(),
                &route
            ));
        }
        for line in [
            "91.221.164.25 via 10.60.26.17 dev wlan0 proto static metric 42760",
            "91.221.164.0/24 via 10.60.26.17 dev wlan0 proto static metric 42760",
            "91.221.164.24 via 10.60.26.18 dev wlan0 proto static metric 42760",
            "91.221.164.24 via 10.60.26.17 dev wlan1 proto static metric 42760",
            "91.221.164.24 via 10.60.26.17 dev wlan0 proto dhcp metric 42760",
            "91.221.164.24 via 10.60.26.17 dev wlan0 proto static metric 600",
        ] {
            assert!(!route_matches_tokens(
                &line.split_whitespace().collect::<Vec<_>>(),
                &route
            ));
        }
    }

    #[test]
    fn parses_lowest_metric_physical_default_route() {
        let output = b"default via 10.0.0.1 dev wg0 metric 1\n\
default via 192.168.1.1 dev enp3s0 proto dhcp src 192.168.1.20 metric 100\n";
        let route = parse_default_route(output).unwrap();
        assert_eq!(route.interface, "enp3s0");
        assert_eq!(route.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(route.source.as_deref(), Some("192.168.1.20"));
    }

    #[test]
    fn parses_direct_default_route_without_gateway() {
        let route = parse_default_route(b"default dev ppp0 proto static metric 50\n").unwrap();

        assert_eq!(route.interface, "ppp0");
        assert_eq!(route.gateway, None);
        assert_eq!(route.source, None);
    }

    #[test]
    fn parses_canonical_local_networks() {
        let routes = parse_local_networks(
            b"2: enp3s0    inet 192.168.1.20/24 brd 192.168.1.255 scope global enp3s0\n",
        );
        assert_eq!(routes, vec!["192.168.1.0/24".parse().unwrap()]);
    }

    #[test]
    fn userspace_state_rejects_mismatched_route_family() {
        let state = UserspaceRouteState {
            format_version: AWG_ROUTE_STATE_FORMAT,
            interface_name: "nlm-awg0".to_string(),
            default_families: Vec::new(),
            routes: vec![UserspaceRoute {
                family: RouteFamily::Ipv6,
                destination: "10.8.0.0/16".to_string(),
            }],
        };

        assert!(validate_userspace_route_state(&state).is_err());
    }

    #[test]
    fn userspace_cleanup_recognizes_only_its_policy_rules() {
        assert!(userspace_rule_is_owned(
            "31120: from all lookup main suppress_prefixlength 0\n",
            AWG_MAIN_RULE_PRIORITY,
        ));
        assert!(userspace_rule_is_owned(
            "31121: from all not fwmark 0xa709 lookup 42761\n",
            AWG_TUNNEL_RULE_PRIORITY,
        ));
        assert!(!userspace_rule_is_owned(
            "31121: from all not fwmark 0xa708 lookup 42761\n",
            AWG_TUNNEL_RULE_PRIORITY,
        ));
    }
}
