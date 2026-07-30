use super::install::{
    create_or_replace_tunnel_service, open_tunnel_service, remove_tunnel_service,
    tunnel_config_path,
};
use super::routes::WindowsRouteManager;
use crate::{ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::DesktopTunnelOptions;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use windows_service::service::ServiceState;

pub(crate) struct WindowsServiceBackend {
    routes: WindowsRouteManager,
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
        Ok(Self { routes })
    }
}

impl ServiceTunnelBackend for WindowsServiceBackend {
    fn start(
        &mut self,
        configuration: &str,
        options: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        self.stop()?;
        if let Err(error) = self.routes.apply(options) {
            let _ = self.routes.cleanup();
            return Err(error);
        }
        let result = (|| {
            let config_path = tunnel_config_path()?;
            write_configuration_atomically(&config_path, configuration)?;
            let service = create_or_replace_tunnel_service(&config_path)?;
            service.start(&[] as &[&str]).map_err(|error| {
                ServiceError::Backend(format!("start WireGuard tunnel service: {error}"))
            })?;
            super::install::wait_until_running(&service)?;
            Ok::<_, ServiceError>(())
        })();
        if let Err(error) = result {
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
