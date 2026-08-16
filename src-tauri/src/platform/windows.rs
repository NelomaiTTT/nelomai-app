use nelomai_client_tunnel::TunnelError;
use nelomai_windows_service::{
    windows::{
        repair_defender_exclusion as run_defender_repair, repair_installation, NamedPipeTransport,
        RepairError,
    },
    DefenderStatus, WindowsTunnelController,
};
use semver::Version;
use std::path::{Path, PathBuf};
use std::time::Duration;

static DEFENDER_STATUS_CACHE: tokio::sync::Mutex<Option<DefenderStatus>> =
    tokio::sync::Mutex::const_new(None);

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
            *DEFENDER_STATUS_CACHE.lock().await = None;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err(tunnel_error("service_unavailable"))
}

pub async fn defender_status() -> Result<DefenderStatus, TunnelError> {
    defender_status_cached(false).await
}

pub async fn refresh_defender_status() -> Result<DefenderStatus, TunnelError> {
    defender_status_cached(true).await
}

pub async fn repair_defender_exclusion() -> Result<DefenderStatus, TunnelError> {
    let client_executable =
        std::env::current_exe().map_err(|_| tunnel_error("helper_resources_unavailable"))?;
    let service_executable = bundled_service_path(&client_executable);
    tokio::task::spawn_blocking(move || {
        run_defender_repair(&service_executable, &client_executable)
    })
    .await
    .map_err(|_| tunnel_error("defender_exclusion_repair_failed"))?
    .map_err(defender_repair_error)?;
    defender_status_cached(true).await
}

pub async fn diagnostic_helper_log() -> Option<String> {
    let controller = tunnel_controller();
    let diagnostics = controller.diagnostics().await.ok();
    let status = controller.defender_status().await.ok();
    if diagnostics.is_none() && status.is_none() {
        return None;
    }
    let defender = status.map_or_else(
        || {
            "state=unavailable dll_present=unknown detail=status_request_failed\n[windows.antivirus]\nstatus=status_request_failed"
                .to_string()
        },
        |status| {
            let products = if status.antivirus_products.is_empty() {
                "none".to_string()
            } else {
                status
                    .antivirus_products
                    .iter()
                    .map(|product| {
                        format!(
                            "name={} state={} signatures={} default={} defender={}",
                            product.name,
                            antivirus_product_state_name(product.state),
                            optional_bool_name(product.signatures_up_to_date),
                            optional_bool_name(product.is_default),
                            product.is_microsoft_defender
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                "state={} dll_present={} detail={}\n[windows.antivirus]\nstatus={}\n{}",
                defender_state_name(status.state),
                status.dll_present,
                status.detail_code.as_deref().unwrap_or("none"),
                status.antivirus_detail_code.as_deref().unwrap_or("ok"),
                products
            )
        },
    );
    Some(format!(
        "[windows.defender]\n{defender}\n{}",
        diagnostics.unwrap_or_default()
    ))
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

fn defender_repair_error(error: RepairError) -> TunnelError {
    match error {
        RepairError::ResourcesUnavailable => tunnel_error("helper_resources_unavailable"),
        RepairError::Cancelled => tunnel_error("defender_exclusion_repair_cancelled"),
        RepairError::AuthorizationUnavailable(_) => {
            tunnel_error("helper_authorization_unavailable")
        }
        RepairError::InstallFailed(_) => tunnel_error("defender_exclusion_repair_failed"),
    }
}

fn defender_state_name(state: nelomai_windows_service::DefenderExclusionState) -> &'static str {
    use nelomai_windows_service::DefenderExclusionState;
    match state {
        DefenderExclusionState::Excluded => "excluded",
        DefenderExclusionState::Missing => "missing",
        DefenderExclusionState::Inactive => "inactive",
        DefenderExclusionState::Unavailable => "unavailable",
    }
}

fn antivirus_product_state_name(
    state: nelomai_windows_service::AntivirusProductState,
) -> &'static str {
    use nelomai_windows_service::AntivirusProductState;
    match state {
        AntivirusProductState::On => "on",
        AntivirusProductState::Off => "off",
        AntivirusProductState::Snoozed => "snoozed",
        AntivirusProductState::Expired => "expired",
        AntivirusProductState::Unknown => "unknown",
    }
}

fn optional_bool_name(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

async fn defender_status_cached(force: bool) -> Result<DefenderStatus, TunnelError> {
    let mut cached = DEFENDER_STATUS_CACHE.lock().await;
    if !force {
        if let Some(status) = cached.as_ref() {
            return Ok(status.clone());
        }
    }
    let status = tunnel_controller()
        .defender_status()
        .await
        .unwrap_or_else(|_| local_defender_status());
    *cached = Some(status.clone());
    Ok(status)
}

fn local_defender_status() -> DefenderStatus {
    let dll_present = std::env::current_exe()
        .map(|path| path.with_file_name("amneziawg-tunnel.dll").is_file())
        .unwrap_or(false);
    DefenderStatus {
        state: nelomai_windows_service::DefenderExclusionState::Unavailable,
        dll_present,
        detail_code: Some("service_status_unavailable".to_string()),
        antivirus_products: Vec::new(),
        antivirus_detail_code: Some("service_status_unavailable".to_string()),
    }
}

fn tunnel_error(code: &str) -> TunnelError {
    TunnelError::Backend(code.to_string())
}
