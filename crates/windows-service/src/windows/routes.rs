use super::install::state_directory;
use super::wide;
use crate::ServiceError;
use ipnet::Ipv4Net;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIfEntry2,
    GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry, IF_TYPE_ETHERNET_CSMACD,
    IF_TYPE_IEEE80211, IF_TYPE_PPP, IF_TYPE_WWANPP, IF_TYPE_WWANPP2, IP_ADDRESS_PREFIX,
    MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::{NET_IF_OPER_STATUS_UP, TUNNEL_TYPE_NONE};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MOVE_FILE_FLAGS,
};

const ROUTE_STATE_FILE: &str = "routes-state.json";
const ROUTE_STATE_FORMAT: u16 = 1;
const ROUTE_METRIC: u32 = 42_760;
const ENDPOINT_ROUTE_METRIC: u32 = 1;
const MAX_STATE_SIZE: u64 = 4 * 1024 * 1024;
const MAX_ROUTES: usize = 16_384;

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
struct OwnedRoute {
    destination: String,
    interface_index: u32,
    gateway: String,
    metric: u32,
}

#[derive(Default, Deserialize, Serialize)]
struct OwnedRouteState {
    format_version: u16,
    policy_hash: Option<String>,
    routes: Vec<OwnedRoute>,
    #[serde(default)]
    pending_routes: Vec<OwnedRoute>,
}

#[derive(Clone, Copy)]
struct WindowsEgress {
    interface_index: u32,
    gateway: Ipv4Addr,
    source: Option<Ipv4Addr>,
}

pub(crate) struct WindowsRouteManager {
    state_path: PathBuf,
    state: OwnedRouteState,
}

impl WindowsRouteManager {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        let state_path = state_directory()?.join(ROUTE_STATE_FILE);
        let state = load_state(&state_path)?;
        Ok(Self { state_path, state })
    }

    pub(crate) fn apply(
        &mut self,
        options: &DesktopTunnelOptions,
        protected_endpoint: Option<IpAddr>,
    ) -> Result<(), ServiceError> {
        self.cleanup()?;
        let plan = Ipv4RoutePlan::from_options(options)
            .map_err(|error| stable_error(error.stable_code()))?;
        let endpoint = match protected_endpoint {
            Some(IpAddr::V4(endpoint)) => Some(endpoint),
            Some(IpAddr::V6(_)) => return Err(stable_error("endpoint_route_unavailable")),
            None => None,
        };
        if plan.excluded_networks.is_empty() && endpoint.is_none() {
            return Ok(());
        }
        let egress = discover_egress()?;
        let mut routes = plan
            .excluded_networks
            .into_iter()
            .map(|network| OwnedRoute {
                destination: network.to_string(),
                interface_index: egress.interface_index,
                gateway: egress.gateway.to_string(),
                metric: ROUTE_METRIC,
            })
            .collect::<Vec<_>>();
        if let Some(endpoint) = endpoint {
            append_protected_endpoint_route(&mut routes, endpoint, egress)?;
        }
        if routes.len() > MAX_ROUTES {
            return Err(stable_error("route_plan_too_large"));
        }
        if routes_presence(&routes)?.into_iter().any(|exists| exists) {
            return Err(stable_error("route_conflict"));
        }
        self.state.policy_hash = plan.policy_hash;
        self.state.pending_routes = routes.clone();
        self.persist()?;

        let mut applied = Vec::with_capacity(routes.len());
        for route in &routes {
            if let Err(error) = create_route(route) {
                self.state.routes = applied;
                self.state.pending_routes.clear();
                let _ = self.persist();
                let _ = self.cleanup();
                return Err(error);
            }
            applied.push(route.clone());
        }
        self.state.routes = applied;
        self.state.pending_routes.clear();
        if let Err(error) = self.persist() {
            let _ = self.cleanup();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn verify_protected_endpoint(
        &self,
        protected_endpoint: Option<IpAddr>,
    ) -> Result<(), ServiceError> {
        let Some(endpoint) = protected_endpoint else {
            return Ok(());
        };
        let IpAddr::V4(endpoint) = endpoint else {
            return Err(stable_error("endpoint_route_unavailable"));
        };
        let destination = format!("{endpoint}/32");
        let Some(expected) = self.state.routes.iter().find(|route| {
            route.destination == destination && route.metric == ENDPOINT_ROUTE_METRIC
        }) else {
            return Err(stable_error("endpoint_route_lost"));
        };
        let selected = best_route(endpoint)?;
        if selected.interface_index != expected.interface_index
            || selected.gateway.to_string() != expected.gateway
        {
            return Err(stable_error("endpoint_route_lost"));
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        self.state.routes =
            remove_present_routes(std::mem::take(&mut self.state.routes), &mut first_error);
        self.state.pending_routes = remove_present_routes(
            std::mem::take(&mut self.state.pending_routes),
            &mut first_error,
        );
        if self.state.routes.is_empty() && self.state.pending_routes.is_empty() {
            self.state.policy_hash = None;
            remove_state(&self.state_path)?;
        } else {
            self.persist()?;
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(crate) fn has_routes(&self) -> bool {
        !self.state.routes.is_empty() || !self.state.pending_routes.is_empty()
    }

    pub(crate) fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        let egress = discover_egress()?;
        let mut networks = local_networks(egress.interface_index)?;
        routes_dedup(&mut networks);
        let networks = networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let material = format!(
            "windows\0{}\0{}\0{}\0{}",
            egress.interface_index,
            egress.gateway,
            egress
                .source
                .map(|value| value.to_string())
                .unwrap_or_default(),
            networks
        );
        let digest = Sha256::digest(material.as_bytes());
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn persist(&self) -> Result<(), ServiceError> {
        if self
            .state
            .routes
            .len()
            .saturating_add(self.state.pending_routes.len())
            > MAX_ROUTES
        {
            return Err(stable_error("route_state_too_large"));
        }
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| stable_error("route_state_serialize_failed"))?;
        if bytes.len() as u64 > MAX_STATE_SIZE {
            return Err(stable_error("route_state_too_large"));
        }
        let temporary = self.state_path.with_extension("json.new");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(stable_error("route_state_write_failed")),
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| stable_error("route_state_write_failed"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| stable_error("route_state_write_failed"))?;
        let flags: MOVE_FILE_FLAGS = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
        let activated = unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(&self.state_path).as_ptr(),
                flags,
            )
        };
        if activated == 0 {
            let _ = fs::remove_file(temporary);
            Err(stable_error("route_state_activate_failed"))
        } else {
            Ok(())
        }
    }
}

fn append_protected_endpoint_route(
    routes: &mut Vec<OwnedRoute>,
    endpoint: Ipv4Addr,
    egress: WindowsEgress,
) -> Result<(), ServiceError> {
    let destination = Ipv4Net::new(endpoint, 32)
        .map_err(|_| stable_error("endpoint_route_unavailable"))?
        .to_string();
    routes.retain(|route| route.destination != destination);
    routes.push(OwnedRoute {
        destination,
        interface_index: egress.interface_index,
        gateway: egress.gateway.to_string(),
        metric: ENDPOINT_ROUTE_METRIC,
    });
    Ok(())
}

fn remove_present_routes(
    routes: Vec<OwnedRoute>,
    first_error: &mut Option<ServiceError>,
) -> Vec<OwnedRoute> {
    if routes.is_empty() {
        return Vec::new();
    }
    let presence = match routes_presence(&routes) {
        Ok(presence) if presence.len() == routes.len() => presence,
        Ok(_) => {
            first_error.get_or_insert_with(|| stable_error("route_table_unavailable"));
            return routes;
        }
        Err(error) => {
            first_error.get_or_insert(error);
            return routes;
        }
    };
    let mut retained = Vec::new();
    for (route, exists) in routes.into_iter().zip(presence) {
        if exists {
            if let Err(error) = delete_route(&route) {
                first_error.get_or_insert(error);
                retained.push(route);
            }
        }
    }
    retained
}

fn discover_egress() -> Result<WindowsEgress, ServiceError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != NO_ERROR || table.is_null() {
        return Err(stable_error("physical_egress_unavailable"));
    }
    let routes = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let selected = routes
        .iter()
        .filter(|route| route.DestinationPrefix.PrefixLength == 0)
        .filter_map(|route| {
            let interface_metric = physical_interface_metric(route)?;
            egress_candidate(
                route,
                interface_metric,
                source_for_interface(route.InterfaceIndex),
            )
        })
        .min_by_key(|(metric, interface_index, _)| (*metric, *interface_index))
        .map(|(_, _, egress)| egress);
    unsafe { FreeMibTable(table.cast()) };
    selected.ok_or_else(|| stable_error("physical_egress_unavailable"))
}

fn egress_candidate(
    route: &MIB_IPFORWARD_ROW2,
    interface_metric: u32,
    source: Option<Ipv4Addr>,
) -> Option<(u32, u32, WindowsEgress)> {
    let gateway = ipv4_from_sockaddr(&route.NextHop)?;
    Some((
        route.Metric.saturating_add(interface_metric),
        route.InterfaceIndex,
        WindowsEgress {
            interface_index: route.InterfaceIndex,
            gateway,
            source,
        },
    ))
}

fn best_route(destination: Ipv4Addr) -> Result<WindowsEgress, ServiceError> {
    let destination = sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let result = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if result != NO_ERROR {
        return Err(stable_error("endpoint_route_unavailable"));
    }
    let gateway = ipv4_from_sockaddr(&route.NextHop)
        .ok_or_else(|| stable_error("endpoint_route_unavailable"))?;
    Ok(WindowsEgress {
        interface_index: route.InterfaceIndex,
        gateway,
        source: ipv4_from_sockaddr(&source),
    })
}

fn physical_interface_metric(route: &MIB_IPFORWARD_ROW2) -> Option<u32> {
    let mut interface = MIB_IF_ROW2 {
        InterfaceLuid: route.InterfaceLuid,
        InterfaceIndex: route.InterfaceIndex,
        ..MIB_IF_ROW2::default()
    };
    if (unsafe { GetIfEntry2(&mut interface) }) != NO_ERROR
        || interface.OperStatus != NET_IF_OPER_STATUS_UP
        || interface.TunnelType != TUNNEL_TYPE_NONE
        || !matches!(
            interface.Type,
            IF_TYPE_ETHERNET_CSMACD
                | IF_TYPE_IEEE80211
                | IF_TYPE_PPP
                | IF_TYPE_WWANPP
                | IF_TYPE_WWANPP2
        )
    {
        return None;
    }
    let mut ip_interface = MIB_IPINTERFACE_ROW {
        Family: AF_INET,
        InterfaceLuid: route.InterfaceLuid,
        InterfaceIndex: route.InterfaceIndex,
        ..MIB_IPINTERFACE_ROW::default()
    };
    if unsafe { GetIpInterfaceEntry(&mut ip_interface) } != NO_ERROR {
        return None;
    }
    Some(ip_interface.Metric)
}

fn source_for_interface(interface_index: u32) -> Option<Ipv4Addr> {
    let destination = sockaddr(Ipv4Addr::new(1, 1, 1, 1));
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let result = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            interface_index,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    (result == NO_ERROR)
        .then(|| ipv4_from_sockaddr(&source))
        .flatten()
}

fn local_networks(interface_index: u32) -> Result<Vec<Ipv4Net>, ServiceError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if result != NO_ERROR || table.is_null() {
        return Err(stable_error("local_networks_unavailable"));
    }
    let routes = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let mut networks = routes
        .iter()
        .filter(|route| route.InterfaceIndex == interface_index)
        .filter(|route| ipv4_from_sockaddr(&route.NextHop) == Some(Ipv4Addr::UNSPECIFIED))
        .filter_map(|route| {
            let address = ipv4_from_sockaddr(&route.DestinationPrefix.Prefix)?;
            let prefix = route.DestinationPrefix.PrefixLength;
            if prefix == 0 || prefix == 32 {
                return None;
            }
            let network = Ipv4Net::new(address, prefix).ok()?;
            let address = network.network();
            (!address.is_loopback() && !address.is_link_local() && !address.is_multicast())
                .then_some(network)
        })
        .collect::<Vec<_>>();
    unsafe { FreeMibTable(table.cast()) };
    routes_dedup(&mut networks);
    Ok(networks)
}

fn create_route(route: &OwnedRoute) -> Result<(), ServiceError> {
    let row = route_row(route)?;
    let result = unsafe { CreateIpForwardEntry2(&row) };
    if result == NO_ERROR {
        Ok(())
    } else {
        Err(stable_error("route_add_failed"))
    }
}

fn routes_presence(routes: &[OwnedRoute]) -> Result<Vec<bool>, ServiceError> {
    let expected = routes
        .iter()
        .map(route_row)
        .collect::<Result<Vec<_>, _>>()?;
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != NO_ERROR || table.is_null() {
        return Err(stable_error("route_table_unavailable"));
    }
    let routes = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    };
    let presence = expected
        .iter()
        .map(|expected| {
            routes
                .iter()
                .any(|candidate| route_rows_match(candidate, expected))
        })
        .collect();
    unsafe { FreeMibTable(table.cast()) };
    Ok(presence)
}

fn route_rows_match(candidate: &MIB_IPFORWARD_ROW2, expected: &MIB_IPFORWARD_ROW2) -> bool {
    candidate.InterfaceIndex == expected.InterfaceIndex
        && candidate.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength
        && ipv4_from_sockaddr(&candidate.DestinationPrefix.Prefix)
            == ipv4_from_sockaddr(&expected.DestinationPrefix.Prefix)
        && ipv4_from_sockaddr(&candidate.NextHop) == ipv4_from_sockaddr(&expected.NextHop)
        && candidate.Metric == expected.Metric
        && candidate.Protocol == expected.Protocol
}

fn delete_route(route: &OwnedRoute) -> Result<(), ServiceError> {
    let row = route_row(route)?;
    let result = unsafe { DeleteIpForwardEntry2(&row) };
    if result == NO_ERROR || result == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(stable_error("route_delete_failed"))
    }
}

fn route_row(route: &OwnedRoute) -> Result<MIB_IPFORWARD_ROW2, ServiceError> {
    let network = route
        .destination
        .parse::<Ipv4Net>()
        .map_err(|_| stable_error("route_state_invalid"))?;
    if network.to_string() != route.destination {
        return Err(stable_error("route_state_invalid"));
    }
    let gateway = route
        .gateway
        .parse::<Ipv4Addr>()
        .map_err(|_| stable_error("route_state_invalid"))?;
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = route.interface_index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr(network.network()),
        PrefixLength: network.prefix_len(),
    };
    row.NextHop = sockaddr(gateway);
    row.Metric = route.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    Ok(row)
}

fn sockaddr(address: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn ipv4_from_sockaddr(address: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    let ipv4 = unsafe { address.Ipv4 };
    if ipv4.sin_family != AF_INET {
        return None;
    }
    Some(Ipv4Addr::from(unsafe {
        ipv4.sin_addr.S_un.S_addr.to_ne_bytes()
    }))
}

fn routes_dedup(networks: &mut Vec<Ipv4Net>) {
    networks.sort_unstable();
    networks.dedup();
}

fn load_state(path: &Path) -> Result<OwnedRouteState, ServiceError> {
    if !path.exists() {
        return Ok(OwnedRouteState {
            format_version: ROUTE_STATE_FORMAT,
            ..OwnedRouteState::default()
        });
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| stable_error("route_state_read_failed"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_STATE_SIZE {
        return Err(stable_error("route_state_invalid"));
    }
    let bytes = fs::read(path).map_err(|_| stable_error("route_state_read_failed"))?;
    let state: OwnedRouteState =
        serde_json::from_slice(&bytes).map_err(|_| stable_error("route_state_invalid"))?;
    if state.format_version != ROUTE_STATE_FORMAT
        || state
            .routes
            .len()
            .saturating_add(state.pending_routes.len())
            > MAX_ROUTES
    {
        return Err(stable_error("route_state_invalid"));
    }
    Ok(state)
}

fn remove_state(path: &Path) -> Result<(), ServiceError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(stable_error("route_state_remove_failed")),
    }
}

fn stable_error(code: &str) -> ServiceError {
    ServiceError::Backend(code.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_row_round_trips_exact_identity() {
        let route = OwnedRoute {
            destination: "203.0.113.0/24".to_string(),
            interface_index: 12,
            gateway: "192.168.1.1".to_string(),
            metric: ROUTE_METRIC,
        };
        let row = route_row(&route).unwrap();
        assert_eq!(row.InterfaceIndex, 12);
        assert_eq!(row.DestinationPrefix.PrefixLength, 24);
        assert_eq!(
            ipv4_from_sockaddr(&row.DestinationPrefix.Prefix),
            Some(Ipv4Addr::new(203, 0, 113, 0))
        );
        assert_eq!(
            ipv4_from_sockaddr(&row.NextHop),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(row.Metric, ROUTE_METRIC);
    }

    #[test]
    fn route_identity_rejects_metric_and_protocol_drift() {
        let route = OwnedRoute {
            destination: "203.0.113.0/24".to_string(),
            interface_index: 12,
            gateway: "192.168.1.1".to_string(),
            metric: ROUTE_METRIC,
        };
        let expected = route_row(&route).unwrap();
        let mut different_metric = expected;
        different_metric.Metric += 1;
        assert!(!route_rows_match(&different_metric, &expected));

        let mut different_protocol = expected;
        different_protocol.Protocol = windows_sys::Win32::Networking::WinSock::MIB_IPPROTO_OTHER;
        assert!(!route_rows_match(&different_protocol, &expected));
    }

    #[test]
    fn endpoint_route_replaces_an_exact_policy_route_with_a_priority_host_route() {
        let mut routes = vec![OwnedRoute {
            destination: "203.0.113.7/32".to_string(),
            interface_index: 12,
            gateway: "192.168.1.1".to_string(),
            metric: ROUTE_METRIC,
        }];
        append_protected_endpoint_route(
            &mut routes,
            Ipv4Addr::new(203, 0, 113, 7),
            WindowsEgress {
                interface_index: 18,
                gateway: Ipv4Addr::new(192, 168, 50, 1),
                source: Some(Ipv4Addr::new(192, 168, 50, 2)),
            },
        )
        .unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "203.0.113.7/32");
        assert_eq!(routes[0].interface_index, 18);
        assert_eq!(routes[0].gateway, "192.168.50.1");
        assert_eq!(routes[0].metric, ENDPOINT_ROUTE_METRIC);
    }

    #[test]
    fn on_link_default_route_is_a_valid_physical_egress() {
        let mut route = MIB_IPFORWARD_ROW2::default();
        route.InterfaceIndex = 21;
        route.Metric = 7;
        route.DestinationPrefix.PrefixLength = 0;
        route.NextHop = sockaddr(Ipv4Addr::UNSPECIFIED);

        let (_, _, egress) =
            egress_candidate(&route, 13, Some(Ipv4Addr::new(100, 64, 12, 34))).unwrap();

        assert_eq!(egress.interface_index, 21);
        assert_eq!(egress.gateway, Ipv4Addr::UNSPECIFIED);
        assert_eq!(egress.source, Some(Ipv4Addr::new(100, 64, 12, 34)));
    }
}
