use super::{OwnedRoute, RouteBackend, RouteScope};
use crate::process::{output_with_timeout, COMMAND_TIMEOUT};
use crate::ServiceError;
use defguard_wireguard_rs::peer::Peer;
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROUTE_METRIC: u32 = 42_760;
const AWG_ROUTE_STATE_FILE: &str = "awg-routes-state.json";
const AWG_ROUTE_STATE_FORMAT: u16 = 1;
const AWG_ROUTE_STATE_MAX_SIZE: u64 = 64 * 1024;
const AWG_FWMARK_TABLE: u32 = 42_761;
const AWG_MAIN_RULE_PRIORITY: u32 = 31_120;
const AWG_TUNNEL_RULE_PRIORITY: u32 = 31_121;

pub(crate) const AWG_FWMARK: u32 = AWG_FWMARK_TABLE;

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

impl UserspaceRouteState {
    fn empty(interface_name: &str) -> Self {
        Self {
            format_version: AWG_ROUTE_STATE_FORMAT,
            interface_name: interface_name.to_string(),
            default_families: Vec::new(),
            routes: Vec::new(),
        }
    }

    fn active(&self) -> bool {
        !self.default_families.is_empty() || !self.routes.is_empty()
    }
}

pub(crate) struct LinuxUserspaceRouteManager {
    ip: PathBuf,
    state_path: PathBuf,
    state: Option<UserspaceRouteState>,
}

impl LinuxUserspaceRouteManager {
    pub(crate) fn new(runtime_directory: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let state_path = runtime_directory.as_ref().join(AWG_ROUTE_STATE_FILE);
        let state = load_userspace_route_state(&state_path)?;
        Ok(Self {
            ip: ip_command()?,
            state_path,
            state,
        })
    }

    pub(crate) fn apply(
        &mut self,
        interface_name: &str,
        peers: &[Peer],
    ) -> Result<(), ServiceError> {
        self.cleanup()?;
        let state = userspace_route_plan(interface_name, peers);
        if !state.active() {
            return Ok(());
        }
        self.ensure_targets_available(&state)?;
        persist_userspace_route_state(&self.state_path, &state)?;
        self.state = Some(state.clone());

        if state.default_families.contains(&RouteFamily::Ipv4)
            && fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", b"1").is_err()
        {
            let _ = self.cleanup();
            return Err(ServiceError::Backend("route_command_failed".to_string()));
        }
        let result = self.apply_state(&state);
        if let Err(error) = result {
            let _ = self.cleanup();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), ServiceError> {
        let Some(state) = self.state.clone() else {
            return Ok(());
        };
        let mut first_error = None;
        for route in state.routes.iter().rev() {
            let query = query_ip(
                &self.ip,
                &[
                    route.family.ip_argument(),
                    "route",
                    "show",
                    "exact",
                    &route.destination,
                ],
            );
            let owned = match query {
                Ok(output) => output.lines().any(|line| {
                    let tokens = line.split_whitespace().collect::<Vec<_>>();
                    value_after(&tokens, "dev") == Some(state.interface_name.as_str())
                        && value_after(&tokens, "proto") == Some("static")
                }),
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if !owned {
                continue;
            }
            let arguments = vec![
                route.family.ip_argument().to_string(),
                "route".to_string(),
                "del".to_string(),
                route.destination.clone(),
                "dev".to_string(),
                state.interface_name.clone(),
                "proto".to_string(),
                "static".to_string(),
            ];
            if let Err(error) = mutate_ip(&self.ip, &arguments, true, "route_del_failed") {
                first_error.get_or_insert(error);
            }
        }
        for family in state.default_families.iter().rev() {
            for priority in [AWG_TUNNEL_RULE_PRIORITY, AWG_MAIN_RULE_PRIORITY] {
                let query = query_ip(
                    &self.ip,
                    &[
                        family.ip_argument(),
                        "rule",
                        "show",
                        "priority",
                        &priority.to_string(),
                    ],
                );
                let owned = match query {
                    Ok(output) => userspace_rule_is_owned(&output, priority),
                    Err(error) => {
                        first_error.get_or_insert(error);
                        continue;
                    }
                };
                if !owned {
                    continue;
                }
                let arguments = userspace_rule_arguments(*family, "del", priority);
                if let Err(error) = mutate_ip(&self.ip, &arguments, true, "route_del_failed") {
                    first_error.get_or_insert(error);
                }
            }
            let query = query_ip(
                &self.ip,
                &[
                    family.ip_argument(),
                    "route",
                    "show",
                    "table",
                    &AWG_FWMARK_TABLE.to_string(),
                ],
            );
            let owned = match query {
                Ok(output) => output.lines().any(|line| {
                    let tokens = line.split_whitespace().collect::<Vec<_>>();
                    tokens.first() == Some(&"default")
                        && value_after(&tokens, "dev") == Some(state.interface_name.as_str())
                }),
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if !owned {
                continue;
            }
            let arguments = vec![
                family.ip_argument().to_string(),
                "route".to_string(),
                "del".to_string(),
                "default".to_string(),
                "dev".to_string(),
                state.interface_name.clone(),
                "table".to_string(),
                AWG_FWMARK_TABLE.to_string(),
            ];
            if let Err(error) = mutate_ip(&self.ip, &arguments, true, "route_del_failed") {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        remove_userspace_route_state(&self.state_path)?;
        self.state = None;
        Ok(())
    }

    pub(crate) fn has_routes(&self) -> bool {
        self.state.as_ref().is_some_and(UserspaceRouteState::active)
    }

    fn ensure_targets_available(&self, state: &UserspaceRouteState) -> Result<(), ServiceError> {
        for family in &state.default_families {
            let rules = query_ip(&self.ip, &[family.ip_argument(), "rule", "show"])?;
            let expected_table = AWG_FWMARK_TABLE.to_string();
            if rules.lines().any(|line| {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                value_after(&tokens, "lookup") == Some(expected_table.as_str())
                    || value_after(&tokens, "table") == Some(expected_table.as_str())
            }) {
                return Err(ServiceError::Backend("route_conflict".to_string()));
            }
            for priority in [AWG_MAIN_RULE_PRIORITY, AWG_TUNNEL_RULE_PRIORITY] {
                ensure_ip_query_empty(
                    &self.ip,
                    &[
                        family.ip_argument(),
                        "rule",
                        "show",
                        "priority",
                        &priority.to_string(),
                    ],
                )?;
            }
            ensure_ip_query_empty(
                &self.ip,
                &[
                    family.ip_argument(),
                    "route",
                    "show",
                    "table",
                    &AWG_FWMARK_TABLE.to_string(),
                ],
            )?;
        }
        for route in &state.routes {
            ensure_ip_query_empty(
                &self.ip,
                &[
                    route.family.ip_argument(),
                    "route",
                    "show",
                    "exact",
                    &route.destination,
                ],
            )?;
        }
        Ok(())
    }

    fn apply_state(&self, state: &UserspaceRouteState) -> Result<(), ServiceError> {
        for route in &state.routes {
            mutate_ip(
                &self.ip,
                &[
                    route.family.ip_argument().to_string(),
                    "route".to_string(),
                    "add".to_string(),
                    route.destination.clone(),
                    "dev".to_string(),
                    state.interface_name.clone(),
                    "proto".to_string(),
                    "static".to_string(),
                ],
                false,
                "route_add_failed",
            )?;
        }
        for family in &state.default_families {
            mutate_ip(
                &self.ip,
                &[
                    family.ip_argument().to_string(),
                    "route".to_string(),
                    "add".to_string(),
                    "default".to_string(),
                    "dev".to_string(),
                    state.interface_name.clone(),
                    "table".to_string(),
                    AWG_FWMARK_TABLE.to_string(),
                ],
                false,
                "route_add_failed",
            )?;
            mutate_ip(
                &self.ip,
                &userspace_rule_arguments(*family, "add", AWG_MAIN_RULE_PRIORITY),
                false,
                "route_add_failed",
            )?;
            mutate_ip(
                &self.ip,
                &userspace_rule_arguments(*family, "add", AWG_TUNNEL_RULE_PRIORITY),
                false,
                "route_add_failed",
            )?;
        }
        Ok(())
    }
}

fn userspace_rule_arguments(family: RouteFamily, action: &str, priority: u32) -> Vec<String> {
    let mut arguments = vec![
        family.ip_argument().to_string(),
        "rule".to_string(),
        action.to_string(),
    ];
    match priority {
        AWG_MAIN_RULE_PRIORITY => arguments.extend([
            "table".to_string(),
            "main".to_string(),
            "suppress_prefixlength".to_string(),
            "0".to_string(),
        ]),
        AWG_TUNNEL_RULE_PRIORITY => arguments.extend([
            "not".to_string(),
            "fwmark".to_string(),
            AWG_FWMARK_TABLE.to_string(),
            "table".to_string(),
            AWG_FWMARK_TABLE.to_string(),
        ]),
        _ => unreachable!("only owned AWG policy rule priorities are used"),
    }
    arguments.extend(["priority".to_string(), priority.to_string()]);
    arguments
}

fn userspace_route_plan(interface_name: &str, peers: &[Peer]) -> UserspaceRouteState {
    let mut state = UserspaceRouteState::empty(interface_name);
    let mut defaults = HashSet::new();
    let mut routes = HashSet::new();
    for allowed_ip in peers.iter().flat_map(|peer| &peer.allowed_ips) {
        let family = if allowed_ip.address.is_ipv4() {
            RouteFamily::Ipv4
        } else {
            RouteFamily::Ipv6
        };
        if allowed_ip.address.is_unspecified() && allowed_ip.cidr == 0 {
            defaults.insert(family);
        } else {
            routes.insert((family, allowed_ip.to_string()));
        }
    }
    state.default_families = defaults.into_iter().collect();
    state.default_families.sort_by_key(|family| match family {
        RouteFamily::Ipv4 => 4,
        RouteFamily::Ipv6 => 6,
    });
    state.routes = routes
        .into_iter()
        .filter(|(family, _)| !state.default_families.contains(family))
        .map(|(family, destination)| UserspaceRoute {
            family,
            destination,
        })
        .collect();
    state
        .routes
        .sort_by(|left, right| left.destination.cmp(&right.destination));
    state
}

fn ensure_ip_query_empty(ip: &Path, arguments: &[&str]) -> Result<(), ServiceError> {
    if query_ip(ip, arguments)?.trim().is_empty() {
        Ok(())
    } else {
        Err(ServiceError::Backend("route_conflict".to_string()))
    }
}

fn query_ip(ip: &Path, arguments: &[&str]) -> Result<String, ServiceError> {
    let output = run(ip, arguments)?;
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

fn mutate_ip(
    ip: &Path,
    arguments: &[String],
    missing_ok: bool,
    error_code: &str,
) -> Result<(), ServiceError> {
    let output = output_with_timeout(
        Command::new(ip)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if output.status.success()
        || (missing_ok && (stderr.contains("No such process") || stderr.contains("No such file")))
    {
        Ok(())
    } else {
        Err(ServiceError::Backend(error_code.to_string()))
    }
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

fn persist_userspace_route_state(
    path: &Path,
    state: &UserspaceRouteState,
) -> Result<(), ServiceError> {
    let bytes = serde_json::to_vec(state)
        .map_err(|_| ServiceError::Backend("route_state_serialize_failed".to_string()))?;
    if bytes.len() as u64 > AWG_ROUTE_STATE_MAX_SIZE {
        return Err(ServiceError::Backend("route_state_too_large".to_string()));
    }
    let temporary = path.with_extension("json.new");
    remove_userspace_route_state(&temporary)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| ServiceError::Backend("route_state_write_failed".to_string()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ServiceError::Backend("route_state_write_failed".to_string()))?;
    fs::rename(&temporary, path)
        .map_err(|_| ServiceError::Backend("route_state_activate_failed".to_string()))
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

    fn owned_route(&self, egress: &Self::Egress, network: Ipv4Net) -> OwnedRoute {
        OwnedRoute {
            destination: network.to_string(),
            interface_identifier: egress.interface.clone(),
            gateway: egress.gateway.clone(),
            metric: Some(ROUTE_METRIC),
        }
    }

    fn add_route(&self, route: &OwnedRoute) -> Result<(), ServiceError> {
        mutate_route(&self.ip, "add", route)
    }

    fn route_exists(&self, route: &OwnedRoute) -> Result<bool, ServiceError> {
        Ok(self
            .route_presence(std::slice::from_ref(route))?
            .into_iter()
            .next()
            .flatten()
            .is_some())
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

    fn remove_route(&self, route: &OwnedRoute, scope: RouteScope) -> Result<(), ServiceError> {
        if scope != RouteScope::Unscoped {
            return Err(ServiceError::Backend("route_state_invalid".to_string()));
        }
        mutate_route(&self.ip, "del", route)
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
    tokens.first() == Some(&route.destination.as_str())
        && value_after(tokens, "via") == route.gateway.as_deref()
        && value_after(tokens, "dev") == Some(route.interface_identifier.as_str())
        && value_after(tokens, "metric").and_then(|value| value.parse::<u32>().ok())
            == Some(expected_metric)
        && value_after(tokens, "proto") == Some("static")
}

fn mutate_route(ip: &Path, action: &str, route: &OwnedRoute) -> Result<(), ServiceError> {
    let metric = route
        .metric
        .ok_or_else(|| ServiceError::Backend("route_state_invalid".to_string()))?
        .to_string();
    let mut arguments = vec![
        "-4".to_string(),
        "route".to_string(),
        action.to_string(),
        route.destination.clone(),
    ];
    if let Some(gateway) = &route.gateway {
        arguments.extend(["via".to_string(), gateway.clone()]);
    }
    arguments.extend([
        "dev".to_string(),
        route.interface_identifier.clone(),
        "metric".to_string(),
        metric,
        "proto".to_string(),
        "static".to_string(),
    ]);
    let output = output_with_timeout(
        Command::new(ip)
            .args(arguments)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(|_| ServiceError::Backend("route_command_failed".to_string()))?;
    if output.status.success()
        || (action == "del" && String::from_utf8_lossy(&output.stderr).contains("No such process"))
    {
        Ok(())
    } else {
        Err(ServiceError::Backend(format!("route_{action}_failed")))
    }
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
    use defguard_wireguard_rs::{key::Key, net::IpAddrMask};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::PermissionsExt;

    fn peer_with_allowed_ips(allowed_ips: Vec<IpAddrMask>) -> Peer {
        let mut peer = Peer::new(Key::new([7; 32]));
        peer.allowed_ips = allowed_ips;
        peer
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
    fn userspace_plan_uses_policy_routing_for_default_routes() {
        let peer = peer_with_allowed_ips(vec![
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            IpAddrMask::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
        ]);

        let state = userspace_route_plan("nlm-awg0", &[peer]);

        assert_eq!(state.default_families, vec![RouteFamily::Ipv4]);
        assert_eq!(
            state.routes,
            vec![UserspaceRoute {
                family: RouteFamily::Ipv6,
                destination: "::1/128".to_string(),
            }]
        );
    }

    #[test]
    fn userspace_plan_deduplicates_specific_routes() {
        let route = IpAddrMask::new(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 0)), 16);
        let state = userspace_route_plan(
            "nlm-awg0",
            &[
                peer_with_allowed_ips(vec![route.clone()]),
                peer_with_allowed_ips(vec![route]),
            ],
        );

        assert!(state.default_families.is_empty());
        assert_eq!(state.routes.len(), 1);
        assert_eq!(state.routes[0].destination, "10.8.0.0/16");
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
        assert_eq!(
            userspace_rule_arguments(RouteFamily::Ipv4, "add", AWG_TUNNEL_RULE_PRIORITY,),
            [
                "-4", "rule", "add", "not", "fwmark", "42761", "table", "42761", "priority",
                "31121",
            ]
            .map(str::to_string)
        );
    }

    #[test]
    fn userspace_route_state_is_private_and_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(AWG_ROUTE_STATE_FILE);
        let state = UserspaceRouteState {
            format_version: AWG_ROUTE_STATE_FORMAT,
            interface_name: "nlm-awg0".to_string(),
            default_families: vec![RouteFamily::Ipv4],
            routes: Vec::new(),
        };

        persist_userspace_route_state(&path, &state).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
        assert_eq!(load_userspace_route_state(&path).unwrap(), Some(state));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_userspace_route_state(&path).is_err());
    }
}
