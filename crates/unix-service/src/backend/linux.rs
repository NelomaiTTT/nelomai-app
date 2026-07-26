use super::build_backend_configuration;
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use defguard_wireguard_rs::{Kernel, WGApi, WireguardInterfaceApi};
use zeroize::Zeroize;

const INTERFACE_NAME: &str = "nlm-wg0";

pub struct LinuxBackend {
    api: WGApi<Kernel>,
    state: ServiceTunnelState,
}

impl LinuxBackend {
    pub fn new() -> Result<Self, ServiceError> {
        let api = WGApi::<Kernel>::new(INTERFACE_NAME).map_err(backend_error)?;
        let state = if api.read_interface_data().is_ok() {
            ServiceTunnelState::Running
        } else {
            ServiceTunnelState::Stopped
        };
        Ok(Self { api, state })
    }

    fn start_inner(&mut self, configuration: &ParsedConfiguration) -> Result<(), ServiceError> {
        if self.api.read_interface_data().is_ok() {
            self.stop_inner()?;
        }

        let mut native = build_backend_configuration(configuration)?;
        native.interface.name = INTERFACE_NAME.to_string();
        self.api.create_interface().map_err(backend_error)?;

        let configured = self.api.configure_interface(&native.interface);
        native.interface.prvkey.zeroize();
        if let Err(error) = configured {
            let _ = self.api.remove_interface();
            return Err(backend_error(error));
        }
        if let Err(error) = self
            .api
            .configure_peer_routing(&native.interface.peers)
            .and_then(|_| self.api.configure_dns(&configuration.dns, &[]))
        {
            let _ = self.api.remove_interface();
            return Err(backend_error(error));
        }
        Ok(())
    }

    fn stop_inner(&mut self) -> Result<(), ServiceError> {
        if self.api.read_interface_data().is_err() {
            return Ok(());
        }
        self.api.remove_interface().map_err(backend_error)
    }
}

impl ServiceTunnelBackend for LinuxBackend {
    fn start(
        &mut self,
        configuration: &ParsedConfiguration,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.state = ServiceTunnelState::Starting;
        match self.start_inner(configuration) {
            Ok(()) => {
                self.state = ServiceTunnelState::Running;
                Ok(self.state)
            }
            Err(error) => {
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
        } else if self.state == ServiceTunnelState::Stopped {
            Ok(ServiceTunnelState::Stopped)
        } else {
            Ok(ServiceTunnelState::Failed)
        }
    }
}

fn backend_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::Backend(error.to_string())
}
