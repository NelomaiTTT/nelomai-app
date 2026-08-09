use nelomai_unix_service::{UnixSocketTransport, UnixTunnelController, DEFAULT_SOCKET_PATH};
use semver::Version;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::Instant;
use tauri::Manager;
use tokio::time::{sleep, Duration};

const HELPER_INSTALL_TIMEOUT: Duration = Duration::from_secs(120);

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
        let amneziawg_go = required_resource(resources, "amneziawg-go")?;
        let status = installer_status(
            Command::new("/usr/bin/pkexec")
                .arg("/bin/sh")
                .arg(installer)
                .arg(uid)
                .arg(helper)
                .arg(amneziawg_go),
        )?;
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
        let amneziawg_go = required_resource(resources, "amneziawg-go")?;
        let status = installer_status(
            Command::new("/usr/bin/osascript")
                .arg(apple_script)
                .arg(installer)
                .arg(uid)
                .arg(helper)
                .arg(wireguard_go)
                .arg(amneziawg_go),
        )?;
        if status.success() {
            Ok(())
        } else {
            Err(tunnel_error("helper_install_cancelled"))
        }
    }
}

fn installer_status(
    command: &mut Command,
) -> Result<ExitStatus, nelomai_client_tunnel::TunnelError> {
    installer_status_with_timeout(command, HELPER_INSTALL_TIMEOUT)
}

fn installer_status_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<ExitStatus, nelomai_client_tunnel::TunnelError> {
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| tunnel_error("helper_authorization_unavailable"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => {
                terminate_installer(&mut child);
                return Err(tunnel_error("helper_authorization_unavailable"));
            }
        }
        if Instant::now() >= deadline {
            terminate_installer(&mut child);
            return Err(tunnel_error("helper_installer_timeout"));
        }
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn terminate_installer(child: &mut std::process::Child) {
    let _ = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_wait_has_a_deadline() {
        let started = Instant::now();
        let result = installer_status_with_timeout(
            Command::new("/bin/sh").args(["-c", "sleep 2"]),
            Duration::from_millis(50),
        );

        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
