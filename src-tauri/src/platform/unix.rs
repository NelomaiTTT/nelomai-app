use nelomai_unix_service::{UnixSocketTransport, UnixTunnelController, DEFAULT_SOCKET_PATH};
use semver::Version;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::Manager;
use tokio::time::{sleep, Duration};

pub type PlatformTunnelController = UnixTunnelController<UnixSocketTransport>;

pub fn tunnel_controller() -> PlatformTunnelController {
    UnixTunnelController::new(UnixSocketTransport::new(DEFAULT_SOCKET_PATH))
}

pub async fn prepare_tunnel(
    app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    let controller = tunnel_controller();
    let current = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| tunnel_error("invalid_app_version"))?;
    if helper_is_current(&controller, &current).await {
        return Ok(());
    }

    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| tunnel_error("helper_resources_unavailable"))?;
    tauri::async_runtime::spawn_blocking(move || install_helper(&resources))
        .await
        .map_err(|_| tunnel_error("helper_installer_failed"))??;

    for _ in 0..30 {
        if helper_is_current(&controller, &current).await {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(tunnel_error("service_unavailable"))
}

async fn helper_is_current(controller: &PlatformTunnelController, current: &Version) -> bool {
    let Ok(installed) = controller.service_version().await else {
        return false;
    };
    Version::parse(&installed).is_ok_and(|installed| installed >= *current)
}

fn install_helper(resources: &Path) -> Result<(), nelomai_client_tunnel::TunnelError> {
    let helper = required_resource(resources, "nelomai-unix-service")?;
    let uid = unsafe { libc::getuid() }.to_string();
    if uid == "0" {
        return Err(tunnel_error("helper_owner_is_root"));
    }

    #[cfg(target_os = "linux")]
    {
        let installer = required_resource(resources, "install-linux.sh")?;
        let status = Command::new("/usr/bin/pkexec")
            .arg("/bin/sh")
            .arg(installer)
            .arg(uid)
            .arg(helper)
            .status()
            .map_err(|_| tunnel_error("helper_authorization_unavailable"))?;
        if status.success() {
            Ok(())
        } else {
            Err(tunnel_error("helper_install_cancelled"))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let installer = required_resource(resources, "install-macos.sh")?;
        let apple_script = required_resource(resources, "install-macos.applescript")?;
        let wireguard_go = required_resource(resources, "wireguard-go")?;
        let status = Command::new("/usr/bin/osascript")
            .arg(apple_script)
            .arg(installer)
            .arg(uid)
            .arg(helper)
            .arg(wireguard_go)
            .status()
            .map_err(|_| tunnel_error("helper_authorization_unavailable"))?;
        if status.success() {
            Ok(())
        } else {
            Err(tunnel_error("helper_install_cancelled"))
        }
    }
}

fn required_resource(
    resources: &Path,
    name: &str,
) -> Result<PathBuf, nelomai_client_tunnel::TunnelError> {
    let path = resources.join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(tunnel_error("helper_resources_unavailable"))
    }
}

fn tunnel_error(code: &str) -> nelomai_client_tunnel::TunnelError {
    nelomai_client_tunnel::TunnelError::Backend(code.to_string())
}
