use super::install::{
    create_or_replace_tunnel_service, open_tunnel_service, remove_tunnel_service,
    tunnel_config_path,
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
}

impl ServiceTunnelBackend for WindowsServiceBackend {
    fn start(
        &mut self,
        configuration: &str,
        options: &DesktopTunnelOptions,
        transport: TunnelTransport,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.stop()?;
        self.endpoint = resolve_endpoint(configuration);
        self.transport = Some(transport);
        if let Err(error) = self.routes.apply(options) {
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
            Ok::<_, ServiceError>(())
        })();
        if let Err(error) = result {
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

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
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
        Ok(match status.current_state {
            ServiceState::Stopped if self.routes.has_routes() => ServiceTunnelState::Failed,
            ServiceState::Stopped => ServiceTunnelState::Stopped,
            ServiceState::StartPending => ServiceTunnelState::Starting,
            ServiceState::Running => ServiceTunnelState::Running,
            ServiceState::StopPending => ServiceTunnelState::Stopping,
            _ => ServiceTunnelState::Failed,
        })
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        let transport = self
            .transport
            .ok_or_else(|| ServiceError::Backend("tunnel_not_running".to_string()))?;
        let (received_bytes, sent_bytes) = interface_counters(transport)?;
        Ok(TunnelMetrics {
            received_bytes,
            sent_bytes,
            probe_target: probe
                .then_some(self.endpoint)
                .flatten()
                .map(|target| target.to_string()),
        })
    }
}

fn read_endpoint_from_file(path: std::path::PathBuf) -> Option<IpAddr> {
    let configuration = zeroize::Zeroizing::new(fs::read_to_string(path).ok()?);
    resolve_endpoint(&configuration)
}

fn read_transport_from_file(path: std::path::PathBuf) -> Option<TunnelTransport> {
    let configuration = zeroize::Zeroizing::new(fs::read_to_string(path).ok()?);
    Some(detect_configuration_transport(&configuration))
}

fn resolve_endpoint(configuration: &str) -> Option<IpAddr> {
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
    (host.trim_matches(['[', ']']), port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|endpoint| endpoint.ip())
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
