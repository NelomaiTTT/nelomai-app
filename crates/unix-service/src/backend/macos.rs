use super::{
    append_userspace_log, apply_and_verify_awg3_configuration, build_backend_configuration,
    configure_interface_after_awg3, host_diagnostic_snapshot, rebind_peers_from_configuration,
    rebind_peers_from_host, rebind_userspace_udp, state_name, transport_name,
    userspace_log_streams, userspace_socket_path, DiagnosticJournal, RebindPeer,
};
use crate::process::{output_with_timeout, status_with_timeout, COMMAND_TIMEOUT};
use crate::routes::{RouteManager, SystemRouteBackend};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{Userspace, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics, TunnelTransport};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const INTERFACE_STATE_FILE: &str = "interface-name";
const DNS_STATE_FILE: &str = "dns-state.json";
const ENDPOINTS_STATE_FILE: &str = "endpoints-state.json";
const START_TIMEOUT: Duration = Duration::from_secs(3);

pub struct MacosBackend {
    wireguard_go: PathBuf,
    amneziawg_go: PathBuf,
    runtime_directory: PathBuf,
    api: Option<WGApi<Userspace>>,
    active_transport: Option<TunnelTransport>,
    rebind_peers: Vec<RebindPeer>,
    endpoints: Vec<SocketAddr>,
    dns_snapshot: Option<DnsSnapshot>,
    routes: RouteManager<SystemRouteBackend>,
    state: ServiceTunnelState,
    diagnostics: DiagnosticJournal,
}

impl MacosBackend {
    pub fn new(
        wireguard_go: impl Into<PathBuf>,
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: impl Into<PathBuf>,
    ) -> Result<Self, ServiceError> {
        let runtime_directory = runtime_directory.into();
        let wireguard_go = wireguard_go.into();
        let amneziawg_go = amneziawg_go.into();
        let mut routes = RouteManager::new(&runtime_directory, SystemRouteBackend::new()?)?;
        let dns_snapshot = load_dns_snapshot(&runtime_directory.join(DNS_STATE_FILE))?;
        let api = recover_api(&runtime_directory)?;
        let rebind_peers = api
            .as_ref()
            .and_then(|api| api.read_interface_data().ok())
            .as_ref()
            .map(rebind_peers_from_host)
            .unwrap_or_default();
        if api.is_none() {
            routes.cleanup()?;
        }
        let endpoints = if api.is_some() {
            load_endpoints(&runtime_directory.join(ENDPOINTS_STATE_FILE))?
        } else {
            remove_regular_file_if_present(&runtime_directory.join(ENDPOINTS_STATE_FILE))
                .map_err(backend_error)?;
            Vec::new()
        };
        let state = if api.is_some() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        let mut diagnostics = DiagnosticJournal::default();
        diagnostics.record(
            "helper_initialized",
            &format!(
                "state={} transport={}",
                state_name(state),
                if api.is_some() { "unknown" } else { "none" }
            ),
        );
        let mut backend = Self {
            wireguard_go,
            amneziawg_go,
            runtime_directory,
            api,
            active_transport: None,
            rebind_peers,
            endpoints,
            dns_snapshot,
            routes,
            state,
            diagnostics,
        };
        if backend.api.is_none() && backend.dns_snapshot.is_some() {
            backend.restore_dns()?;
        }
        Ok(backend)
    }

    fn start_inner(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        if self.api.is_some() || self.dns_snapshot.is_some() || self.routes.has_routes() {
            self.stop_inner()?;
        }
        let executable = match configuration.transport {
            TunnelTransport::WireGuard => self.wireguard_go.clone(),
            TunnelTransport::AmneziaWg3 => self.amneziawg_go.clone(),
        };
        validate_root_owned_binary(&executable)?;
        validate_runtime_directory(&self.runtime_directory)?;

        let mut native = build_backend_configuration(configuration)?;
        self.routes.apply(options)?;
        self.capture_dns()?;
        let ifname = match launch_userspace_tunnel(
            &executable,
            &self.runtime_directory,
            configuration.transport,
        ) {
            Ok(ifname) => ifname,
            Err(error) => {
                let _ = self.stop_inner();
                return Err(error);
            }
        };
        self.active_transport = Some(configuration.transport);
        native.interface.name = ifname.clone();
        let api = match WGApi::<Userspace>::new(&ifname) {
            Ok(api) => api,
            Err(error) => {
                let _ = self.stop_inner();
                return Err(backend_error(error));
            }
        };
        self.endpoints = native.endpoints;
        self.api = Some(api);
        if let Err(error) = save_endpoints(
            &self.runtime_directory.join(ENDPOINTS_STATE_FILE),
            &self.endpoints,
        ) {
            let _ = self.stop_inner();
            return Err(error);
        }

        let configured = configure_interface_after_awg3(
            configuration.awg3.as_ref(),
            |parameters| apply_and_verify_awg3_configuration(&ifname, parameters),
            || {
                self.api
                    .as_ref()
                    .expect("WireGuard API assigned")
                    .configure_interface(&native.interface)
                    .map_err(backend_error)
            },
        );
        native.interface.prvkey.zeroize();
        if let Err(error) = configured {
            let _ = self.stop_inner();
            return Err(error);
        }
        if let Err(error) = self
            .api
            .as_ref()
            .expect("WireGuard API assigned")
            .configure_peer_routing(&native.interface.peers)
        {
            let _ = self.stop_inner();
            return Err(backend_error(error));
        }
        if !configuration.dns.is_empty() {
            if let Err(error) = apply_dns(
                self.dns_snapshot
                    .as_ref()
                    .expect("DNS snapshot captured before tunnel start"),
                &configuration.dns,
            ) {
                let _ = self.stop_inner();
                return Err(error);
            }
        }
        self.rebind_peers = if configuration.transport == TunnelTransport::AmneziaWg3 {
            rebind_peers_from_configuration(configuration)
        } else {
            Vec::new()
        };
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        self.active_transport = None;
        self.rebind_peers.clear();
        let mut first_error = None;
        if let Some(api) = self.api.take() {
            if let Err(error) = api.remove_interface() {
                if api.read_interface_data().is_ok() {
                    self.api = Some(api);
                    return Err(backend_error(error));
                }
            }
            for endpoint in self.endpoints.drain(..) {
                if let Err(error) = api.remove_endpoint_routing(&endpoint.to_string()) {
                    first_error.get_or_insert_with(|| backend_error(error));
                }
            }
        }
        if let Err(error) = self.restore_dns() {
            first_error.get_or_insert(error);
        }
        let state_file = self.runtime_directory.join(INTERFACE_STATE_FILE);
        if let Err(error) = remove_regular_file_if_present(&state_file) {
            first_error.get_or_insert_with(|| backend_error(error));
        }
        if let Err(error) =
            remove_regular_file_if_present(&self.runtime_directory.join(ENDPOINTS_STATE_FILE))
        {
            first_error.get_or_insert_with(|| backend_error(error));
        }
        if let Err(error) = self.routes.cleanup() {
            first_error.get_or_insert(error);
        }

        first_error.map_or(Ok(()), Err)
    }

    fn capture_dns(&mut self) -> Result<(), ServiceError> {
        let snapshot = snapshot_dns()?;
        save_dns_snapshot(&self.runtime_directory.join(DNS_STATE_FILE), &snapshot)?;
        self.dns_snapshot = Some(snapshot);
        Ok(())
    }

    fn restore_dns(&mut self) -> Result<(), ServiceError> {
        let Some(snapshot) = self.dns_snapshot.as_ref() else {
            return Ok(());
        };
        restore_dns_snapshot(snapshot)?;
        remove_regular_file_if_present(&self.runtime_directory.join(DNS_STATE_FILE))
            .map_err(backend_error)?;
        self.dns_snapshot = None;
        Ok(())
    }

    fn diagnostic_snapshot(&self) -> String {
        let transport = if self.active_transport.is_none() && self.api.is_some() {
            "unknown"
        } else {
            transport_name(self.active_transport)
        };
        let mut snapshot = format!(
            "state={}\ntransport={transport}\nroutes_active={}\ndns_snapshot_active={}",
            state_name(self.state),
            self.routes.has_routes(),
            self.dns_snapshot.is_some(),
        );
        match self
            .api
            .as_ref()
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))
            .and_then(|api| api.read_interface_data().map_err(backend_error))
        {
            Ok(host) => {
                snapshot.push('\n');
                snapshot.push_str(&host_diagnostic_snapshot(&host));
            }
            Err(error) => {
                snapshot.push_str("\nuapi=unavailable\nuapi_error_code=");
                snapshot.push_str(error.code());
            }
        }
        snapshot
    }
}

impl ServiceTunnelBackend for MacosBackend {
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Starting;
        self.diagnostics.record(
            "start_begin",
            &format!(
                "transport={}",
                transport_name(Some(configuration.transport))
            ),
        );
        match self.start_inner(configuration, options) {
            Ok(()) => {
                self.state = ServiceTunnelState::Running;
                let snapshot = self.diagnostic_snapshot().replace('\n', " ");
                self.diagnostics.record("start_ok", &snapshot);
                Ok(self.state)
            }
            Err(error) => {
                let _ = self.stop_inner();
                self.state = ServiceTunnelState::Failed;
                self.diagnostics
                    .record("start_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Stopping;
        let snapshot = self.diagnostic_snapshot().replace('\n', " ");
        self.diagnostics.record("stop_begin", &snapshot);
        match self.stop_inner() {
            Ok(()) => {
                self.state = ServiceTunnelState::Stopped;
                self.diagnostics.record("stop_ok", "");
                Ok(self.state)
            }
            Err(error) => {
                self.state = ServiceTunnelState::Failed;
                self.diagnostics
                    .record("stop_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        if let Some(api) = &self.api {
            if api.read_interface_data().is_err() {
                return Ok(ServiceTunnelState::Failed);
            }
        }
        if self.api.is_none() && self.routes.has_routes() {
            return Ok(ServiceTunnelState::Failed);
        }
        Ok(self.state)
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        let host = self
            .api
            .as_ref()
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))?
            .read_interface_data()
            .map_err(backend_error)?;
        let received_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.rx_bytes));
        let sent_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.tx_bytes));
        let latest_handshake_epoch_millis = host
            .peers
            .values()
            .filter_map(|peer| peer.last_handshake)
            .filter_map(|handshake| handshake.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .max();
        let probe_target = probe
            .then(|| {
                host.peers
                    .values()
                    .find_map(|peer| peer.endpoint.map(|endpoint| endpoint.ip().to_string()))
            })
            .flatten();
        Ok(TunnelMetrics {
            received_bytes,
            sent_bytes,
            latest_handshake_epoch_millis,
            probe_target,
        })
    }

    fn diagnostics(&self) -> Result<String, ServiceError> {
        let mut output = self.diagnostics.render(&self.diagnostic_snapshot());
        append_userspace_log(&mut output, &self.runtime_directory);
        Ok(output)
    }

    fn rebind_udp(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        if self.api.is_none() {
            return Err(ServiceError::Backend("tunnel_not_running".to_string()));
        }
        let ifname = read_interface_name(&self.runtime_directory.join(INTERFACE_STATE_FILE))?;
        let before = self.diagnostic_snapshot().replace('\n', " ");
        self.diagnostics.record("udp_rebind_begin", &before);
        match rebind_userspace_udp(&ifname, &self.rebind_peers) {
            Ok(()) => {
                let after = self.diagnostic_snapshot().replace('\n', " ");
                self.diagnostics.record("udp_rebind_ok", &after);
                Ok(ServiceTunnelState::Running)
            }
            Err(error) => {
                self.diagnostics
                    .record("udp_rebind_error", &format!("code={}", error.code()));
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
struct DnsSnapshot {
    services: Vec<ServiceDns>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
struct ServiceDns {
    name: String,
    servers: Vec<IpAddr>,
    search_domains: Vec<String>,
}

fn snapshot_dns() -> Result<DnsSnapshot, ServiceError> {
    let services = parse_network_services(&run_networksetup(&["-listallnetworkservices"])?.stdout);
    let mut snapshots = Vec::with_capacity(services.len());
    for service in services {
        let dns_output = run_networksetup(&["-getdnsservers", &service])?;
        let search_output = run_networksetup(&["-getsearchdomains", &service])?;
        snapshots.push(ServiceDns {
            name: service,
            servers: parse_dns_servers(&dns_output.stdout),
            search_domains: parse_search_domains(&search_output.stdout),
        });
    }
    Ok(DnsSnapshot {
        services: snapshots,
    })
}

fn apply_dns(snapshot: &DnsSnapshot, dns: &[IpAddr]) -> Result<(), ServiceError> {
    let values: Vec<String> = dns.iter().map(ToString::to_string).collect();
    for service in &snapshot.services {
        let mut args = vec!["-setdnsservers".to_string(), service.name.clone()];
        args.extend(values.iter().cloned());
        run_networksetup_owned(&args)?;
    }
    Ok(())
}

fn restore_dns_snapshot(snapshot: &DnsSnapshot) -> Result<(), ServiceError> {
    let mut first_error = None;
    for service in &snapshot.services {
        if let Err(error) = set_network_values(
            "-setdnsservers",
            &service.name,
            service.servers.iter().map(ToString::to_string),
        ) {
            first_error.get_or_insert(error);
        }
        if let Err(error) = set_network_values(
            "-setsearchdomains",
            &service.name,
            service.search_domains.iter().cloned(),
        ) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn set_network_values(
    command: &str,
    service: &str,
    values: impl Iterator<Item = String>,
) -> Result<(), ServiceError> {
    let mut args = vec![command.to_string(), service.to_string()];
    args.extend(values);
    if args.len() == 2 {
        args.push("Empty".to_string());
    }
    run_networksetup_owned(&args).map(|_| ())
}

fn parse_network_services(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("An asterisk") && !line.starts_with('*')
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_dns_servers(output: &[u8]) -> Vec<IpAddr> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

fn parse_search_domains(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("There aren't any"))
        .map(ToOwned::to_owned)
        .collect()
}

fn run_networksetup(args: &[&str]) -> Result<Output, ServiceError> {
    let args: Vec<String> = args.iter().map(|value| (*value).to_string()).collect();
    run_networksetup_owned(&args)
}

fn run_networksetup_owned(args: &[String]) -> Result<Output, ServiceError> {
    let output = output_with_timeout(
        Command::new(NETWORKSETUP)
            .args(args)
            .env("LANG", "C")
            .env("LC_ALL", "C"),
        COMMAND_TIMEOUT,
    )
    .map_err(backend_error)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ServiceError::Backend(
            "network_configuration_failed".to_string(),
        ))
    }
}

fn launch_userspace_tunnel(
    executable: &Path,
    runtime_directory: &Path,
    transport: TunnelTransport,
) -> Result<String, ServiceError> {
    let state_file = runtime_directory.join(INTERFACE_STATE_FILE);
    remove_regular_file_if_present(&state_file).map_err(backend_error)?;

    let status = status_with_timeout(
        &mut userspace_tunnel_command(executable, &state_file, runtime_directory),
        COMMAND_TIMEOUT,
    )
    .map_err(backend_error)?;
    if !status.success() {
        return Err(ServiceError::Backend(
            userspace_start_error(transport, false).to_string(),
        ));
    }

    let started = Instant::now();
    while started.elapsed() < START_TIMEOUT {
        if let Ok(ifname) = read_interface_name(&state_file) {
            let socket = userspace_socket_path(&ifname);
            if socket.exists() {
                return Ok(ifname);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(ServiceError::Backend(
        userspace_start_error(transport, true).to_string(),
    ))
}

fn userspace_start_error(transport: TunnelTransport, timed_out: bool) -> &'static str {
    match (transport, timed_out) {
        (TunnelTransport::WireGuard, false) => "wireguard_go_start_failed",
        (TunnelTransport::WireGuard, true) => "wireguard_go_start_timeout",
        (TunnelTransport::AmneziaWg3, false) => "amneziawg_go_start_failed",
        (TunnelTransport::AmneziaWg3, true) => "amneziawg_go_start_timeout",
    }
}

fn userspace_tunnel_command(
    executable: &Path,
    state_file: &Path,
    runtime_directory: &Path,
) -> Command {
    let mut command = Command::new(executable);
    command
        .arg("utun")
        .env("WG_TUN_NAME_FILE", state_file)
        .stdin(Stdio::null());
    if let Some((stdout, stderr)) = userspace_log_streams(runtime_directory) {
        command
            .env("LOG_LEVEL", "error")
            .stdout(stdout)
            .stderr(stderr);
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    command
}

fn read_interface_name(path: &Path) -> Result<String, ServiceError> {
    let mut value = String::new();
    fs::File::open(path)
        .and_then(|mut file| file.read_to_string(&mut value))
        .map_err(backend_error)?;
    let value = value.trim();
    let suffix = value
        .strip_prefix("utun")
        .ok_or_else(|| ServiceError::Backend("invalid_interface_name".to_string()))?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ServiceError::Backend("invalid_interface_name".to_string()));
    }
    Ok(value.to_string())
}

fn recover_api(runtime_directory: &Path) -> Result<Option<WGApi<Userspace>>, ServiceError> {
    let state_file = runtime_directory.join(INTERFACE_STATE_FILE);
    if !state_file.exists() {
        return Ok(None);
    }
    let ifname = read_interface_name(&state_file)?;
    let socket = userspace_socket_path(&ifname);
    if !socket.exists() {
        remove_regular_file_if_present(&state_file).map_err(backend_error)?;
        return Ok(None);
    }
    WGApi::<Userspace>::new(ifname)
        .map(Some)
        .map_err(backend_error)
}

fn validate_root_owned_binary(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend("untrusted_wireguard_go".to_string()));
    }
    Ok(())
}

fn validate_runtime_directory(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend(
            "untrusted_runtime_directory".to_string(),
        ));
    }
    Ok(())
}

fn save_dns_snapshot(path: &Path, snapshot: &DnsSnapshot) -> Result<(), ServiceError> {
    save_json_state(path, snapshot)
}

fn load_dns_snapshot(path: &Path) -> Result<Option<DnsSnapshot>, ServiceError> {
    if !path.exists() {
        return Ok(None);
    }
    validate_state_file(path, "untrusted_dns_state")?;
    let file = fs::File::open(path).map_err(backend_error)?;
    serde_json::from_reader(file)
        .map(Some)
        .map_err(backend_error)
}

fn save_endpoints(path: &Path, endpoints: &[SocketAddr]) -> Result<(), ServiceError> {
    save_json_state(path, endpoints)
}

fn load_endpoints(path: &Path) -> Result<Vec<SocketAddr>, ServiceError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    validate_state_file(path, "untrusted_endpoint_state")?;
    let file = fs::File::open(path).map_err(backend_error)?;
    serde_json::from_reader(file).map_err(backend_error)
}

fn save_json_state<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), ServiceError> {
    let temporary = path.with_extension("tmp");
    remove_regular_file_if_present(&temporary).map_err(backend_error)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(backend_error)?;
    serde_json::to_writer(&mut file, value).map_err(backend_error)?;
    file.flush().map_err(backend_error)?;
    file.sync_all().map_err(backend_error)?;
    fs::rename(&temporary, path).map_err(backend_error)
}

fn validate_state_file(path: &Path, error_code: &str) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(backend_error)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ServiceError::Backend(error_code.to_string()));
    }
    Ok(())
}

fn remove_regular_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to remove a non-regular state path",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn network_service_parser_ignores_disabled_and_explanatory_lines() {
        let services = parse_network_services(
            b"An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB LAN\n",
        );

        assert_eq!(services, ["Wi-Fi"]);
    }

    #[test]
    fn dns_parser_accepts_only_ip_addresses() {
        assert_eq!(
            parse_dns_servers(b"8.8.8.8\n2001:4860:4860::8888\n"),
            [
                "8.8.8.8".parse::<IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
            ]
        );
        assert!(parse_dns_servers(b"There aren't any DNS Servers set.\n").is_empty());
    }

    #[test]
    fn search_domain_parser_ignores_the_empty_state_message() {
        assert_eq!(
            parse_search_domains(b"corp.example\nlab.example\n"),
            ["corp.example", "lab.example"]
        );
        assert!(
            parse_search_domains(b"There aren't any Search Domains set on Wi-Fi.\n").is_empty()
        );
    }

    #[test]
    fn userspace_tunnel_receives_no_configuration_or_key_arguments() {
        let runtime = tempfile::tempdir().expect("create runtime directory");
        let command = userspace_tunnel_command(
            Path::new("/Library/PrivilegedHelperTools/wireguard-go"),
            Path::new("/var/run/nelomai/interface-name"),
            runtime.path(),
        );
        let args: Vec<&OsStr> = command.get_args().collect();

        assert_eq!(args, [OsStr::new("utun")]);
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "WG_TUN_NAME_FILE"
                && value == Some(OsStr::new("/var/run/nelomai/interface-name"))));
    }
}
