use nelomai_windows_service::{windows::NamedPipeTransport, WindowsTunnelController};
use semver::Version;

pub type PlatformTunnelController = WindowsTunnelController<NamedPipeTransport>;

pub fn tunnel_controller() -> PlatformTunnelController {
    WindowsTunnelController::new(NamedPipeTransport::new())
}

pub async fn prepare_tunnel() -> Result<(), nelomai_client_tunnel::TunnelError> {
    let installed = tunnel_controller().service_version().await?;
    let installed = Version::parse(&installed).map_err(|_| tunnel_error("service_outdated"))?;
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| tunnel_error("invalid_app_version"))?;
    if installed >= current {
        Ok(())
    } else {
        Err(tunnel_error("service_outdated"))
    }
}

fn tunnel_error(code: &str) -> nelomai_client_tunnel::TunnelError {
    nelomai_client_tunnel::TunnelError::Backend(code.to_string())
}
