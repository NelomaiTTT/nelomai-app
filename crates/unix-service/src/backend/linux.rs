use super::build_backend_configuration;
use crate::routes::{RouteManager, SystemRouteBackend};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{Kernel, WGApi, WireguardInterfaceApi};
use nelomai_client_tunnel::{DesktopTunnelOptions, TunnelMetrics};
use std::path::Path;
use zeroize::Zeroize;

const INTERFACE_NAME: &str = "nlm-wg0";

pub struct LinuxBackend {
    api: WGApi<Kernel>,
    routes: RouteManager<SystemRouteBackend>,
    state: ServiceTunnelState,
}

impl LinuxBackend {
    pub fn new(runtime_directory: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let api = WGApi::<Kernel>::new(INTERFACE_NAME).map_err(backend_error)?;
        let mut routes = RouteManager::new(runtime_directory, SystemRouteBackend::new()?)?;
        let running = api.read_interface_data().is_ok();
        if !running {
            routes.cleanup()?;
        }
        let state = if running {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        Ok(Self { api, routes, state })
    }

    fn start_inner(
        &mut self,
        configuration: &ParsedConfiguration,
        options: &DesktopTunnelOptions,
    ) -> Result<(), ServiceError> {
        if self.api.read_interface_data().is_ok() || self.routes.has_routes() {
            self.stop_inner()?;
        }

        let mut native = build_backend_configuration(configuration)?;
        native.interface.name = INTERFACE_NAME.to_string();
        self.routes.apply(options)?;
        self.api.create_interface().map_err(backend_error)?;

        let configured = self.api.configure_interface(&native.interface);
        native.interface.prvkey.zeroize();
        if let Err(error) = configured {
            let _ = self.api.remove_interface();
            let _ = self.routes.cleanup();
            return Err(backend_error(error));
        }
        if let Err(error) = self
            .api
            .configure_peer_routing(&native.interface.peers)
            .and_then(|_| self.api.configure_dns(&configuration.dns, &[]))
        {
            let _ = self.api.remove_interface();
            let _ = self.routes.cleanup();
            return Err(backend_error(error));
        }
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        let mut first_error = None;
        if self.api.read_interface_data().is_ok() {
            if let Err(error) = self.api.remove_interface() {
                first_error.get_or_insert_with(|| backend_error(error));
            }
        }
        if let Err(error) = self.routes.cleanup() {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
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
        if self.api.read_interface_data().is_ok() {
            Ok(ServiceTunnelState::Running)
        } else if self.state == ServiceTunnelState::Stopped && !self.routes.has_routes() {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Ok(ServiceTunnelState::Failed)
        }
    }

    fn physical_network_fingerprint(&self) -> Result<String, ServiceError> {
        self.routes.physical_network_fingerprint()
    }

    fn metrics(&self, probe: bool) -> Result<TunnelMetrics, ServiceError> {
        let host = self.api.read_interface_data().map_err(backend_error)?;
        let received_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.rx_bytes));
        let sent_bytes = host
            .peers
            .values()
            .fold(0u64, |total, peer| total.saturating_add(peer.tx_bytes));
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
            probe_target,
        })
    }
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}
