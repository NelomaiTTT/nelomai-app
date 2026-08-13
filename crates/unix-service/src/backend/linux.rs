use super::{
    apply_and_verify_awg3_configuration, build_backend_configuration, userspace_socket_path,
};
use crate::process::{status_with_timeout, COMMAND_TIMEOUT};
use crate::routes::{LinuxUserspaceRouteManager, RouteManager, SystemRouteBackend, AWG_FWMARK};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{host::Host, Kernel, Userspace, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics, TunnelTransport};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const WIREGUARD_INTERFACE_NAME: &str = "nlm-wg0";
const AMNEZIAWG_INTERFACE_NAME: &str = "nlm-awg0";
const START_TIMEOUT: Duration = Duration::from_secs(3);

pub struct LinuxBackend {
    wireguard_api: WGApi<Kernel>,
    amneziawg_api: WGApi<Userspace>,
    amneziawg_go: PathBuf,
    active_transport: Option<TunnelTransport>,
    amneziawg_routes: LinuxUserspaceRouteManager,
    routes: RouteManager<SystemRouteBackend>,
    state: ServiceTunnelState,
}

impl LinuxBackend {
    pub fn new(
        amneziawg_go: impl Into<PathBuf>,
        runtime_directory: impl AsRef<Path>,
    ) -> Result<Self, ServiceError> {
        let wireguard_api =
            WGApi::<Kernel>::new(WIREGUARD_INTERFACE_NAME).map_err(backend_error)?;
        let amneziawg_api =
            WGApi::<Userspace>::new(AMNEZIAWG_INTERFACE_NAME).map_err(backend_error)?;
        let mut amneziawg_routes = LinuxUserspaceRouteManager::new(&runtime_directory)?;
        let mut routes = RouteManager::new(runtime_directory, SystemRouteBackend::new()?)?;
        let wireguard_running = wireguard_api.read_interface_data().is_ok();
        let amneziawg_running = amneziawg_api.read_interface_data().is_ok();
        if wireguard_running && amneziawg_running {
            return Err(ServiceError::Backend(
                "multiple_tunnel_interfaces_detected".to_string(),
            ));
        }
        let active_transport = if wireguard_running {
            Some(TunnelTransport::WireGuard)
        } else if amneziawg_running {
            Some(TunnelTransport::AmneziaWg3)
        } else {
            amneziawg_routes.cleanup()?;
            routes.cleanup()?;
            None
        };
        let state = if active_transport.is_some() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        Ok(Self {
            wireguard_api,
            amneziawg_api,
            amneziawg_go: amneziawg_go.into(),
            active_transport,
            amneziawg_routes,
            routes,
            state,
        })
    }

    fn start_inner(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        if self.active_transport.is_some()
            || self.amneziawg_routes.has_routes()
            || self.routes.has_routes()
        {
            self.stop_inner()?;
        }

        let mut native = build_backend_configuration(configuration)?;
        let interface_name = match configuration.transport {
            TunnelTransport::WireGuard => WIREGUARD_INTERFACE_NAME,
            TunnelTransport::AmneziaWg3 => AMNEZIAWG_INTERFACE_NAME,
        };
        native.interface.name = interface_name.to_string();
        if configuration.transport == TunnelTransport::AmneziaWg3 {
            native.interface.fwmark = Some(AWG_FWMARK);
        }
        self.routes.apply(options)?;

        match configuration.transport {
            TunnelTransport::WireGuard => {
                self.wireguard_api
                    .create_interface()
                    .map_err(backend_error)?;
            }
            TunnelTransport::AmneziaWg3 => {
                validate_root_owned_binary(&self.amneziawg_go)?;
                launch_amneziawg_go(&self.amneziawg_go, interface_name)?;
            }
        }
        self.active_transport = Some(configuration.transport);

        let configured = match configuration.transport {
            TunnelTransport::WireGuard => self.wireguard_api.configure_interface(&native.interface),
            TunnelTransport::AmneziaWg3 => {
                self.amneziawg_api.configure_interface(&native.interface)
            }
        };
        native.interface.prvkey.zeroize();
        if let Err(error) = configured {
            let _ = self.stop_inner();
            return Err(backend_error(error));
        }
        if let Some(parameters) = configuration.awg3.as_ref() {
            if let Err(error) = apply_and_verify_awg3_configuration(interface_name, parameters) {
                let _ = self.stop_inner();
                return Err(error);
            }
        }

        let configured_routes: Result<(), ServiceError> = match configuration.transport {
            TunnelTransport::WireGuard => self
                .wireguard_api
                .configure_peer_routing(&native.interface.peers)
                .and_then(|_| self.wireguard_api.configure_dns(&configuration.dns, &[]))
                .map_err(backend_error),
            TunnelTransport::AmneziaWg3 => self
                .amneziawg_routes
                .apply(interface_name, &native.interface.peers)
                .and_then(|_| {
                    self.amneziawg_api
                        .configure_dns(&configuration.dns, &[])
                        .map_err(backend_error)
                }),
        };
        if let Err(error) = configured_routes {
            let _ = self.stop_inner();
            return Err(error);
        }
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        let transport = self.active_transport.take();
        let mut first_error = None;
        if let Err(error) = self.amneziawg_routes.cleanup() {
            first_error.get_or_insert(error);
        }
        let interface_error = match transport {
            Some(TunnelTransport::WireGuard) => self.wireguard_api.remove_interface().err(),
            Some(TunnelTransport::AmneziaWg3) => self.amneziawg_api.remove_interface().err(),
            None => None,
        };
        if let Some(error) = interface_error {
            first_error.get_or_insert_with(|| backend_error(error));
        }
        if let Err(error) = self.routes.cleanup() {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }

    fn read_active_interface(&self) -> Result<Host, ServiceError> {
        match self.active_transport {
            Some(TunnelTransport::WireGuard) => self
                .wireguard_api
                .read_interface_data()
                .map_err(backend_error),
            Some(TunnelTransport::AmneziaWg3) => self
                .amneziawg_api
                .read_interface_data()
                .map_err(backend_error),
            None => Err(ServiceError::Backend("tunnel_not_running".to_string())),
        }
    }
}

impl ServiceTunnelBackend for LinuxBackend {
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Starting;
        match self.start_inner(configuration, options) {
            Ok(()) => {
                self.state = ServiceTunnelState::Running;
                Ok(self.state)
            }
            Err(error) => {
                let _ = self.stop_inner();
                self.state = ServiceTunnelState::Failed;
                Err(error)
            }
        }
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Stopping;
        match self.stop_inner() {
            Ok(()) => {
                self.state = ServiceTunnelState::Stopped;
                Ok(self.state)
            }
            Err(error) => {
                self.state = ServiceTunnelState::Failed;
                Err(error)
            }
        }
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        if self.active_transport.is_some() && self.read_active_interface().is_ok() {
            Ok(ServiceTunnelState::Running)
        } else if self.active_transport.is_none()
            && self.state == ServiceTunnelState::Stopped
            && !self.amneziawg_routes.has_routes()
            && !self.routes.has_routes()
        {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Ok(ServiceTunnelState::Failed)
        }
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        let host = self.read_active_interface()?;
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
}

fn launch_amneziawg_go(executable: &Path, interface_name: &str) -> Result<(), ServiceError> {
    let socket_path = userspace_socket_path(interface_name);
    if socket_path.exists() {
        return Err(ServiceError::Backend(
            "amneziawg_interface_already_exists".to_string(),
        ));
    }
    let status = status_with_timeout(
        Command::new(executable)
            .arg(interface_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
        COMMAND_TIMEOUT,
    )
    .map_err(backend_error)?;
    if !status.success() {
        return Err(ServiceError::Backend(
            "amneziawg_go_start_failed".to_string(),
        ));
    }
    let started = Instant::now();
    while started.elapsed() < START_TIMEOUT {
        if socket_path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(ServiceError::Backend(
        "amneziawg_go_start_timeout".to_string(),
    ))
}

fn validate_root_owned_binary(path: &Path) -> Result<(), ServiceError> {
    let metadata = std::fs::symlink_metadata(path).map_err(backend_error)?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(ServiceError::Backend("untrusted_amneziawg_go".to_string()));
    }
    Ok(())
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}
