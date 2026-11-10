use nelomai_contracts::dispatcher::{
    DispatcherRequest, DispatcherResponse, EngineIdentity, Installation,
};
use nelomai_unix_service::{
    ServiceError, UnixSocketTransport, UnixTunnelController, DEFAULT_SOCKET_PATH,
};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::Instant;
use tauri::Manager;
use tokio::time::{sleep, Duration};

const HELPER_INSTALL_TIMEOUT: Duration = Duration::from_secs(120);

pub type PlatformTunnelController = UnixTunnelController<UnixSocketTransport>;

pub fn common_tunnel_controller(
    binding: nelomai_contracts::dispatcher::CommonEngineBinding,
) -> PlatformTunnelController {
    UnixTunnelController::new(UnixSocketTransport::new(DEFAULT_SOCKET_PATH).for_common(binding))
}

pub async fn prepare_tunnel(
    app: tauri::AppHandle<tauri::Wry>,
    allow_install: bool,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    let resources = app
        .path()
        .resource_dir()
        .map_err(|_| tunnel_error("helper_resources_unavailable"))?;
    let expected = Installation::production(Path::new("/unused"))
        .and_then(|trust| trust.manifest_identity(&resources.join("runtime")))
        .map_err(|_| tunnel_error("verified_helper_identity_unavailable"))?;
    if helper_is_current(&expected).await? {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        // launchctl bootstrap can return before the service socket is ready.
        let readiness_deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < readiness_deadline {
            sleep(Duration::from_millis(100)).await;
            if helper_is_current(&expected).await? {
                return Ok(());
            }
        }
        // Only initial application startup may repair/migrate once. An old
        // helper rejects an updated broker before even serving Version, so
        // that migration cannot be distinguished from IPC failure here.
        if !allow_install {
            return Err(tunnel_error("helper_update_required"));
        }
    }
    #[cfg(target_os = "linux")]
    let _ = allow_install;
    tauri::async_runtime::spawn_blocking(move || install_helper(&resources))
        .await
        .map_err(|_| tunnel_error("helper_installer_failed"))??;

    #[cfg(target_os = "macos")]
    let readiness_deadline = Instant::now() + Duration::from_secs(3);
    for _ in 0..30 {
        // An IPC call already has a bounded timeout. Do not multiply a stalled
        // macOS service timeout by thirty while waiting for launchd readiness.
        #[cfg(target_os = "macos")]
        if Instant::now() >= readiness_deadline {
            break;
        }
        if helper_is_current(&expected).await? {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    Err(tunnel_error("service_unavailable"))
}

async fn helper_is_current(
    expected: &EngineIdentity,
) -> Result<bool, nelomai_client_tunnel::TunnelError> {
    let expected = expected.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let retries = if cfg!(target_os = "linux") { 2 } else { 0 };
        probe_helper(&expected, retries, || {
            nelomai_unix_service::dispatcher_exchange(&DispatcherRequest::Version {
                contract_version: 1,
            })
        })
    })
    .await
    .unwrap_or(Ok(false))
}

fn probe_helper(
    expected: &EngineIdentity,
    retries: usize,
    mut version: impl FnMut() -> Result<DispatcherResponse, ServiceError>,
) -> Result<bool, nelomai_client_tunnel::TunnelError> {
    let mut response = version();
    let retryable = |response: &Result<_, ServiceError>| {
        matches!(
            response,
            Err(ServiceError::DispatcherTimeout | ServiceError::DispatcherBusy)
        )
    };
    let recovering = retries > 0 && retryable(&response);
    if recovering {
        for _ in 0..retries {
            if matches!(response, Err(ServiceError::DispatcherBusy)) {
                thread::sleep(Duration::from_millis(250));
            }
            response = version();
            if !retryable(&response) {
                break;
            }
        }
    }

    let actual = response
        .ok()
        .filter(|response| response.ok && response.contract_version == 1)
        .and_then(|response| response.identity);
    match actual {
        Some(actual) => Ok(actual.manifest_sha256 == expected.manifest_sha256
            && actual.container_version == expected.container_version),
        // A busy dispatcher must return a valid identity before startup can
        // decide whether its installation needs repair.
        None if recovering => Err(tunnel_error("service_unavailable")),
        None => Ok(false),
    }
}

fn install_helper(resources: &Path) -> Result<(), nelomai_client_tunnel::TunnelError> {
    let helper = required_resource(resources, "dispatcher/1/nelomai-unix-service")?;
    let layout = resources.join("runtime");
    let broker = std::fs::canonicalize(
        std::env::current_exe().map_err(|_| tunnel_error("common_broker_unavailable"))?,
    )
    .map_err(|_| tunnel_error("common_broker_unavailable"))?;
    // AppImage's per-launch FUSE path is not the installed common broker.
    // Task 9's launcher must hand off here before auth initialization.
    #[cfg(target_os = "linux")]
    if broker != Path::new("/usr/local/libexec/nelomai/common/AppDir/usr/bin/nelomai-app") {
        return Err(tunnel_error("installed_common_broker_required"));
    }
    nelomai_contracts::dispatcher::trusted(&broker, 0)
        .map_err(|_| tunnel_error("installed_common_broker_required"))?;
    let uid = unsafe { libc::getuid() }.to_string();
    if uid == "0" {
        return Err(tunnel_error("helper_owner_is_root"));
    }

    #[cfg(target_os = "linux")]
    {
        let installer = required_resource(resources, "install-linux.sh")?;
        let status = installer_status(
            Command::new("/usr/bin/pkexec")
                .arg("/bin/sh")
                .arg(installer)
                .arg(uid)
                .arg(helper)
                .arg(layout)
                .arg(broker),
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
        let status = installer_status(
            Command::new("/usr/bin/osascript")
                .arg(apple_script)
                .arg(installer)
                .arg(uid)
                .arg(helper)
                .arg(layout)
                .arg(broker),
        )?;
        if status.success() {
            Ok(())
        } else {
            Err(tunnel_error("helper_install_cancelled"))
        }
    }
}

pub(crate) fn installer_status(
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
    fn linux_helper_probe_distinguishes_temporary_errors_from_installation() {
        let expected = EngineIdentity {
            slot: nelomai_contracts::RuntimeSlot::Latest,
            runtime_version: "0.4.2".into(),
            runtime_contract_version: 1,
            container_version: "0.4.2".into(),
            manifest_sha256: "a".repeat(64),
        };
        let mut stable = expected.clone();
        stable.slot = nelomai_contracts::RuntimeSlot::Stable;
        stable.runtime_version = "0.3.11".into();
        let mut outdated = expected.clone();
        outdated.manifest_sha256 = "b".repeat(64);
        let timeout = Err(ServiceError::DispatcherTimeout);
        let busy = Err(ServiceError::DispatcherBusy);

        for (responses, outcome) in [
            (
                vec![
                    busy.clone(),
                    Ok(DispatcherResponse::success(stable.clone(), false)),
                ],
                Ok(true),
            ),
            (
                vec![busy.clone(), timeout.clone(), busy],
                Err(tunnel_error("service_unavailable")),
            ),
            (
                vec![
                    timeout.clone(),
                    Ok(DispatcherResponse::success(stable, false)),
                ],
                Ok(true),
            ),
            (
                vec![
                    timeout.clone(),
                    Ok(DispatcherResponse::success(outdated, false)),
                ],
                Ok(false),
            ),
            (
                vec![timeout.clone(), timeout.clone(), timeout.clone()],
                Err(tunnel_error("service_unavailable")),
            ),
            (
                vec![timeout, Ok(DispatcherResponse::failure())],
                Err(tunnel_error("service_unavailable")),
            ),
            (
                vec![Err(ServiceError::Backend("helper unavailable".into()))],
                Ok(false),
            ),
        ] {
            let mut responses = responses.into_iter();
            let result = probe_helper(&expected, 2, || responses.next().expect("probe budget"));
            assert_eq!(
                result.map_err(|error| error.to_string()),
                outcome.map_err(|error| error.to_string())
            );
            assert!(responses.next().is_none());
        }
    }

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
