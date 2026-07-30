use super::install::state_directory;
use crate::ServiceError;
use ipnet::Ipv4Net;
use nelomai_client_tunnel::{DesktopTunnelOptions, Ipv4RoutePlan};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetBestRoute2, GetIfEntry2,
    GetIpForwardTable2, InitializeIpForwardEntry, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IF_TYPE_WWANPP, IF_TYPE_WWANPP2, IP_ADDRESS_PREFIX, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{NET_IF_OPER_STATUS_UP, TUNNEL_TYPE_NONE};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IN_ADDR_0, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_INET,
};

const ROUTE_STATE_FILE: &str = "routes-state.json";
const ROUTE_STATE_FORMAT: u16 = 1;
const ROUTE_METRIC: u32 = 42_760;
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
}

#[derive(Clone, Copy)]
struct WindowsEgress {
    interface_index: u32,
    gateway: Ipv4Addr,
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

    pub(crate) fn apply(&mut self, options: &DesktopTunnelOptions) -> Result<(), ServiceError> {
        self.cleanup()?;
        let plan = Ipv4RoutePlan::from_options(options)
            .map_err(|error| stable_error(error.stable_code()))?;
        if !plan.active() {
            return Ok(());
        }
        let egress = discover_egress()?;
        let local = if plan.exclude_local_networks {
            local_networks(egress.interface_index)?
        } else {
            Vec::new()
        };
        let plan = plan
            .merged_with_local_networks(local)
            .map_err(|error| stable_error(error.stable_code()))?;
        self.state.policy_hash = plan.policy_hash;
        self.persist()?;

        for network in plan.excluded_networks {
            let route = OwnedRoute {
                destination: network.to_string(),
                interface_index: egress.interface_index,
                gateway: egress.gateway.to_string(),
                metric: ROUTE_METRIC,
            };
            self.state.routes.push(route.clone());
            if let Err(error) = self.persist() {
                let _ = self.cleanup();
                return Err(error);
            }
            if let Err(error) = create_route(&route) {
                self.state.routes.pop();
                let _ = self.persist();
                let _ = self.cleanup();
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        let mut retained = Vec::new();
        for route in std::mem::take(&mut self.state.routes) {
            if let Err(error) = delete_route(&route) {
                first_error.get_or_insert(error);
                retained.push(route);
            }
        }
        self.state.routes = retained;
        if self.state.routes.is_empty() {
            self.state.policy_hash = None;
            remove_state(&self.state_path)?;
        } else {
            self.persist()?;
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(crate) fn has_routes(&self) -> bool {
        !self.state.routes.is_empty()
    }

    fn persist(&self) -> Result<(), ServiceError> {
        if self.state.routes.len() > MAX_ROUTES {
            return Err(stable_error("route_state_too_large"));
        }
        let bytes = serde_json::to_vec(&self.state)
            .map_err(|_| stable_error("route_state_serialize_failed"))?;
        if bytes.len() as u64 > MAX_STATE_SIZE {
            return Err(stable_error("route_state_too_large"));
        }
        let temporary = self.state_path.with_extension("json.new");
        fs::write(&temporary, bytes).map_err(|_| stable_error("route_state_write_failed"))?;
        fs::rename(&temporary, &self.state_path)
            .map_err(|_| stable_error("route_state_activate_failed"))
    }
}

fn discover_egress() -> Result<WindowsEgress, ServiceError> {
    let destination = sockaddr(Ipv4Addr::new(1, 1, 1, 1));
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
        return Err(stable_error("physical_egress_unavailable"));
    }

    let mut interface = MIB_IF_ROW2 {
        InterfaceLuid: route.InterfaceLuid,
        InterfaceIndex: route.InterfaceIndex,
        ..MIB_IF_ROW2::default()
    };
    if unsafe { GetIfEntry2(&mut interface) } != NO_ERROR
        || interface.OperStatus != NET_IF_OPER_STATUS_UP
        || interface.TunnelType != TUNNEL_TYPE_NONE
        || !matches!(
            interface.Type,
            IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211 | IF_TYPE_WWANPP | IF_TYPE_WWANPP2
        )
    {
        return Err(stable_error("physical_egress_unavailable"));
    }
    Ok(WindowsEgress {
        interface_index: route.InterfaceIndex,
        gateway: ipv4_from_sockaddr(&route.NextHop)
            .ok_or_else(|| stable_error("physical_egress_unavailable"))?,
    })
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
    if state.format_version != ROUTE_STATE_FORMAT || state.routes.len() > MAX_ROUTES {
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
}
