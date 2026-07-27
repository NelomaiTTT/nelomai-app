use nelomai_client_tunnel::TunnelError;
use nelomai_windows_service::{
    windows::{repair_installation, NamedPipeTransport, RepairError},
    WindowsTunnelController,
};
use semver::Version;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub type PlatformTunnelController = WindowsTunnelController<NamedPipeTransport>;

pub fn tunnel_controller() -> PlatformTunnelController {
    WindowsTunnelController::new(NamedPipeTransport::new())
}

pub async fn prepare_tunnel() -> Result<(), TunnelError> {
    if verify_service_version().await.is_ok() {
        return Ok(());
    }

    let client_executable =
        std::env::current_exe().map_err(|_| tunnel_error("helper_resources_unavailable"))?;
    let service_executable = bundled_service_path(&client_executable);
    tokio::task::spawn_blocking(move || {
        repair_installation(&service_executable, &client_executable)
    })
    .await
    .map_err(|_| tunnel_error("helper_authorization_unavailable"))?
    .map_err(repair_error)?;

    for _ in 0..20 {
        if verify_service_version().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(tunnel_error("service_unavailable"))
}

async fn verify_service_version() -> Result<(), TunnelError> {
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

fn bundled_service_path(client_executable: &Path) -> PathBuf {
    client_executable.with_file_name("nelomai-windows-service.exe")
}

fn repair_error(error: RepairError) -> TunnelError {
    match error {
        RepairError::ResourcesUnavailable => tunnel_error("helper_resources_unavailable"),
        RepairError::Cancelled => tunnel_error("helper_install_cancelled"),
        RepairError::AuthorizationUnavailable(_) => {
            tunnel_error("helper_authorization_unavailable")
        }
        RepairError::InstallFailed(_) => tunnel_error("service_unavailable"),
    }
}

fn tunnel_error(code: &str) -> TunnelError {
    TunnelError::Backend(code.to_string())
}
