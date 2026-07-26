use super::install::{
    create_or_replace_tunnel_service, open_tunnel_service, remove_tunnel_service,
    tunnel_config_path,
};
use crate::{ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use windows_service::service::ServiceState;

pub(crate) struct WindowsServiceBackend;

impl WindowsServiceBackend {
    pub(crate) fn new() -> Self {
        Self
    }
}

impl ServiceTunnelBackend for WindowsServiceBackend {
    fn start(&mut self, configuration: &str) -> Result<ServiceTunnelState, ServiceError> {
        remove_tunnel_service()?;
        let config_path = tunnel_config_path()?;
        write_configuration_atomically(&config_path, configuration)?;
        let service = create_or_replace_tunnel_service(&config_path)?;
        if let Err(error) = service.start(&[] as &[&str]) {
            let _ = remove_tunnel_service();
            let _ = fs::remove_file(&config_path);
            return Err(ServiceError::Backend(format!(
                "start WireGuard tunnel service: {error}"
            )));
        }
        super::install::wait_until_running(&service)?;
        Ok(ServiceTunnelState::Running)
    }

    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        remove_tunnel_service()?;
        let _ = fs::remove_file(tunnel_config_path()?);
        Ok(ServiceTunnelState::Stopped)
    }

    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        let Some(service) = open_tunnel_service()? else {
            return Ok(ServiceTunnelState::Stopped);
        };
        let status = service
            .query_status()
            .map_err(|error| ServiceError::Backend(format!("query tunnel service: {error}")))?;
        Ok(match status.current_state {
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
