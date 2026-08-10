use super::install::{
    create_or_replace_tunnel_service, open_tunnel_service, read_service_diagnostics,
    record_service_diagnostic, record_service_message, remove_tunnel_service, tunnel_config_path,
};
use super::routes::WindowsRouteManager;
use crate::{ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::{
    detect_configuration_transport, DesktopTunnelOptions, TunnelMetrics, TunnelTransport,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use windows_service::service::ServiceState;
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

const TUNNEL_INTERFACE_NAME: &str = "nelomai";

pub(crate) struct WindowsServiceBackend {
    routes: WindowsRouteManager,
    endpoint: Option<IpAddr>,
    transport: Option<TunnelTransport>,
}

impl WindowsServiceBackend {
    pub(crate) fn new() -> Result<Self, ServiceError> {
        let mut routes = WindowsRouteManager::new()?;
        let tunnel_active = match open_tunnel_service()? {
            Some(service) => {
                service
                    .query_status()
                    .map_err(|error| {
                        ServiceError::Backend(format!("query tunnel service: {error}"))
                    })?
                    .current_state
                    != ServiceState::Stopped
            }
            None => false,
        };
        if !tunnel_active {
            routes.cleanup()?;
        }
        let endpoint = tunnel_active
            .then(|| tunnel_config_path().ok().and_then(read_endpoint_from_file))
            .flatten();
        let transport = tunnel_active
            .then(|| tunnel_config_path().ok().and_then(read_transport_from_file))
            .flatten();
        Ok(Self {
            routes,
            endpoint,
            transport,
        })
    }

    fn protected_endpoint(&self) -> Option<IpAddr> {
        (self.transport == Some(TunnelTransport::AmneziaWg3))
            .then_some(self.endpoint)
            .flatten()
    }
}

impl ServiceTunnelBackend for WindowsServiceBackend {
    fn start(
        &mut self,
        configuration: &str,
        options: &DesktopTunnelOptions,
        transport: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.stop()?;
        let endpoint = resolve_endpoint(configuration);
        if transport == TunnelTransport::AmneziaWg3 && !matches!(endpoint, Some(IpAddr::V4(_))) {
            return Err(ServiceError::Backend(
                "endpoint_route_unavailable".to_string(),
            ));
        }
        let pinned_configuration = if transport == TunnelTransport::AmneziaWg3 {
            Some(pin_configuration_endpoint(
                configuration,
                endpoint.expect("validated IPv4 AmneziaWG endpoint"),
            )?)
        } else {
            None
        };
        self.endpoint = endpoint;
        self.transport = Some(transport);
        let configuration = pinned_configuration
            .as_ref()
            .map_or(configuration, |value| value.as_str());
        let protected_endpoint = self.protected_endpoint();
        if let Err(error) = self.routes.apply(options, protected_endpoint) {
            self.endpoint = None;
            self.transport = None;
            let _ = self.routes.cleanup();
            return Err(error);
        }
        let result = (|| {
            let config_path = tunnel_config_path()?;
            write_configuration_atomically(&config_path, configuration)?;
            let service = create_or_replace_tunnel_service(&config_path, transport)?;
            service
                .start(&[] as &[&str])
                .map_err(|error| match transport {
                    TunnelTransport::WireGuard => {
                        ServiceError::Backend(format!("start WireGuard tunnel service: {error}"))
                    }
                    TunnelTransport::AmneziaWg3 => {
                        ServiceError::Backend("amneziawg_service_start_failed".to_string())
                    }
                })?;
            if let Err(error) = super::install::wait_until_running(&service) {
                return Err(match transport {
                    TunnelTransport::WireGuard => error,
                    TunnelTransport::AmneziaWg3 => {
                        ServiceError::Backend("amneziawg_service_start_failed".to_string())
                    }
                });
            }
            self.routes
                .verify_protected_endpoint(self.protected_endpoint())?;
            Ok::<_, ServiceError>(())
        })();
        if let Err(error) = result {
            record_service_diagnostic("tunnel start failed", &error);
            self.endpoint = None;
            self.transport = None;
            let config_path = tunnel_config_path().ok();
            let _ = remove_tunnel_service();
            if let Some(config_path) = config_path {
                let _ = fs::remove_file(config_path);
            }
            let _ = self.routes.cleanup();
            return Err(error);
        }
        record_service_message(
            "tunnel started",
            match transport {
                TunnelTransport::WireGuard => "transport=wireguard endpoint_route=native",
                TunnelTransport::AmneziaWg3 => "transport=amneziawg_3 endpoint_route=verified",
            },
        );
        Ok(ServiceTunnelState::Running)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.endpoint = None;
        self.transport = None;
        let mut first_error = remove_tunnel_service().err();
        match tunnel_config_path() {
            Ok(path) => {
                if let Err(error) = fs::remove_file(path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        first_error.get_or_insert_with(|| {
                            ServiceError::Backend(format!("remove tunnel config: {error}"))
                        });
                    }
                }
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.routes.cleanup() {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(ServiceTunnelState::Stopped), Err)
    }

    fn status(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        let Some(service) = open_tunnel_service()? else {
            return Ok(if self.routes.has_routes() {
                ServiceTunnelState::Failed
            } else {
                ServiceTunnelState::Stopped
            });
        };
        let status = service
            .query_status()
            .map_err(|error| ServiceError::Backend(format!("query tunnel service: {error}")))?;
        let state = match status.current_state {
            ServiceState::Stopped if self.routes.has_routes() => ServiceTunnelState::Failed,
            ServiceState::Stopped => ServiceTunnelState::Stopped,
            ServiceState::StartPending => ServiceTunnelState::Starting,
            ServiceState::Running => ServiceTunnelState::Running,
            ServiceState::StopPending => ServiceTunnelState::Stopping,
            _ => ServiceTunnelState::Failed,
        };
        if state == ServiceTunnelState::Running {
            if let Err(error) = self
                .routes
                .verify_protected_endpoint(self.protected_endpoint())
            {
                record_service_diagnostic("unsafe endpoint route detected", &error);
                let _ = self.stop();
                return Ok(ServiceTunnelState::Failed);
            }
        }
        Ok(state)
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&mut self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        if let Err(error) = self
            .routes
            .verify_protected_endpoint(self.protected_endpoint())
        {
            record_service_diagnostic("unsafe endpoint route detected", &error);
            let _ = self.stop();
            return Err(error);
        }
        let transport = self
            .transport
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))?;
        let (received_bytes, sent_bytes) = interface_counters(transport)?;
        Ok(TunnelMetrics {
            received_bytes,
            sent_bytes,
            latest_handshake_epoch_millis: None,
            probe_target: probe
                .then_some(self.endpoint)
                .flatten()
                .map(|target| target.to_string()),
        })
    }

    fn diagnostics(&mut self) -> Result<String, ServiceError> {
        let service = read_service_diagnostics()?;
        let ringlogger = match super::ringlogger::read_amneziawg_ringlogger() {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => format!("ringlogger_unavailable: {error}"),
        };
        let service = tail_utf8(&service, 24 * 1024);
        let prefix = format!("[nelomai.service]\n{service}\n[amneziawg.ringlogger]\n");
        let ringlogger = tail_utf8(&ringlogger, (64_usize * 1024).saturating_sub(prefix.len()));
        Ok(format!("{prefix}{ringlogger}"))
    }
}

fn tail_utf8(value: &str, maximum: usize) -> &str {
    if value.len() <= maximum {
        return value;
    }
    let mut start = value.len() - maximum;
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    &value[start..]
}

fn read_endpoint_from_file(path: std::path::PathBuf) -> Option<IpAddr> {
    let configuration = zeroize::Zeroizing::new(fs::read_to_string(path).ok()?);
    resolve_endpoint(&configuration)
}

fn read_transport_from_file(path: std::path::PathBuf) -> Option<TunnelTransport> {
    let configuration = zeroize::Zeroizing::new(fs::read_to_string(path).ok()?);
    Some(detect_configuration_transport(&configuration))
}

pub(crate) fn resolve_endpoint(configuration: &str) -> Option<IpAddr> {
    let value = configuration.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("Endpoint")
            .then(|| value.trim())
    })?;
    if let Ok(endpoint) = value.parse::<std::net::SocketAddr>() {
        return Some(endpoint.ip());
    }
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let endpoints = (host.trim_matches(['[', ']']), port)
        .to_socket_addrs()
        .ok()?
        .collect::<Vec<_>>();
    endpoints
        .iter()
        .find(|endpoint| endpoint.is_ipv4())
        .or_else(|| endpoints.first())
        .map(|endpoint| endpoint.ip())
}

fn pin_configuration_endpoint(
    configuration: &str,
    endpoint: IpAddr,
) -> Result<zeroize::Zeroizing<String>, ServiceError> {
    let IpAddr::V4(endpoint) = endpoint else {
        return Err(ServiceError::Backend(
            "endpoint_route_unavailable".to_string(),
        ));
    };
    let mut output = zeroize::Zeroizing::new(String::with_capacity(configuration.len()));
    let mut replacements = 0_u8;
    for segment in configuration.split_inclusive('\n') {
        let (line_with_optional_cr, newline) = segment
            .strip_suffix('\n')
            .map_or((segment, ""), |line| (line, "\n"));
        let (line, carriage_return) = line_with_optional_cr
            .strip_suffix('\r')
            .map_or((line_with_optional_cr, ""), |line| (line, "\r"));
        let Some((key, value)) = line.split_once('=') else {
            output.push_str(line);
            output.push_str(carriage_return);
            output.push_str(newline);
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("Endpoint") {
            output.push_str(line);
            output.push_str(carriage_return);
            output.push_str(newline);
            continue;
        }
        let (_, port) = value
            .trim()
            .rsplit_once(':')
            .ok_or_else(|| ServiceError::Backend("endpoint_route_unavailable".to_string()))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| ServiceError::Backend("endpoint_route_unavailable".to_string()))?;
        replacements = replacements.saturating_add(1);
        output.push_str("Endpoint = ");
        output.push_str(&endpoint.to_string());
        output.push(':');
        output.push_str(&port.to_string());
        output.push_str(carriage_return);
        output.push_str(newline);
    }
    if replacements != 1 {
        return Err(ServiceError::Backend(
            "endpoint_route_unavailable".to_string(),
        ));
    }
    Ok(output)
}

fn interface_counters(transport: TunnelTransport) -> Result<(u64, u64), ServiceError> {
    let interface_name = match transport {
        TunnelTransport::WireGuard => TUNNEL_INTERFACE_NAME,
        TunnelTransport::AmneziaWg3 => crate::AMNEZIAWG_TUNNEL_SERVICE_NAME,
    };
    let mut table = std::ptr::null_mut::<MIB_IF_TABLE2>();
    let result = unsafe { GetIfTable2(&mut table) };
    if result != NO_ERROR || table.is_null() {
        return Err(ServiceError::Backend(format!(
            "read tunnel interface table: {result}"
        )));
    }
    let counters = unsafe {
        let entries =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        entries
            .iter()
            .find(|entry| wide_string(&entry.Alias).eq_ignore_ascii_case(interface_name))
            .map(|entry| (entry.InOctets, entry.OutOctets))
    };
    unsafe { FreeMibTable(table.cast()) };
    counters.ok_or_else(|| ServiceError::Backend("tunnel interface not found".to_string()))
}

fn wide_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn write_configuration_atomically(path: &Path, configuration: &str) -> Result<(), ServiceError> {
    let temporary = path.with_extension("conf.new");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| ServiceError::Backend(format!("create tunnel config: {error}")))?;
    file.write_all(configuration.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| ServiceError::Backend(format!("write tunnel config: {error}")))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| ServiceError::Backend(format!("replace tunnel config: {error}")))?;
    }
    fs::rename(&temporary, path)
        .map_err(|error| ServiceError::Backend(format!("activate tunnel config: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn pins_a_hostname_endpoint_to_the_protected_ipv4_address() {
        let configuration = "[Interface]\r\nPrivateKey = secret\r\n[Peer]\r\nEndpoint = 5a.nelomai.ru:51820\r\nAllowedIPs = 0.0.0.0/0\r\n";
        let pinned =
            pin_configuration_endpoint(configuration, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
                .unwrap();

        assert!(pinned.contains("Endpoint = 203.0.113.7:51820\r\n"));
        assert!(!pinned.contains("5a.nelomai.ru"));
        assert!(pinned.contains("PrivateKey = secret"));
    }

    #[test]
    fn rejects_multiple_endpoints_that_cannot_all_be_route_protected() {
        let configuration = "[Peer]\nEndpoint = one.example:1\n[Peer]\nEndpoint = two.example:2\n";
        let error =
            pin_configuration_endpoint(configuration, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))
                .unwrap_err();

        assert_eq!(error.code(), "endpoint_route_unavailable");
    }
}
