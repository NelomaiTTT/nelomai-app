#[cfg(target_os = "android")]
pub mod android_updater;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix;
#[cfg(desktop)]
pub mod updater;
#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "android")]
pub type PlatformTunnelController =
    tauri_plugin_tunnel_android::AndroidTunnelController<tauri::Wry>;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) type PlatformTunnelController =
    nelomai_unix_service::UnixTunnelController<crate::runtime::RemoteTransport>;
#[cfg(windows)]
pub(crate) type PlatformTunnelController =
    nelomai_windows_service::WindowsTunnelController<crate::runtime::RemoteTransport>;

#[cfg(target_os = "android")]
pub fn tunnel_controller(app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    tauri_plugin_tunnel_android::AndroidTunnelController::new(app)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn tunnel_controller(_app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    nelomai_unix_service::UnixTunnelController::new(crate::runtime::RemoteTransport)
}

#[cfg(windows)]
pub async fn diagnostic_helper_log(tunnel: &PlatformTunnelController) -> Option<String> {
    let log = tunnel.diagnostics().await.ok();
    let defender = defender_status(false).await.ok();
    windows::format_diagnostic_helper_log(log, defender)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn diagnostic_helper_log(tunnel: &PlatformTunnelController) -> Option<String> {
    tunnel.diagnostics().await.ok()
}

#[cfg(windows)]
pub fn tunnel_controller(_app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    nelomai_windows_service::WindowsTunnelController::new(crate::runtime::RemoteTransport)
}

#[cfg(target_os = "android")]
pub async fn prepare_tunnel(
    app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    use tauri_plugin_tunnel_android::TunnelAndroidExt;

    let probe = app
        .tunnel_android()
        .probe()
        .map_err(|error| nelomai_client_tunnel::TunnelError::Backend(error.to_string()))?;
    if !probe.backend_available {
        return Err(nelomai_client_tunnel::TunnelError::Backend(
            probe
                .error
                .unwrap_or_else(|| "tunnel_backend_unavailable".to_string()),
        ));
    }
    if probe.permission_granted {
        return Ok(());
    }

    let permission = app
        .tunnel_android()
        .request_vpn_permission()
        .map_err(|error| nelomai_client_tunnel::TunnelError::Backend(error.to_string()))?;
    if permission.permission_granted {
        Ok(())
    } else {
        Err(nelomai_client_tunnel::TunnelError::Backend(
            "vpn_permission_denied".to_string(),
        ))
    }
}

#[cfg(not(target_os = "android"))]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn prepare_tunnel(
    app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    let _ = app;
    crate::runtime::native()
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common runtime unavailable".into())
        })?
        .control(crate::runtime::NativeControl::Prepare)
        .await
        .map(|_| ())
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common preparation failed".into())
        })
}

#[cfg(windows)]
pub async fn prepare_tunnel(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    private_prepare().await
}

#[cfg(windows)]
pub async fn prepare_tunnel_for_stop(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    private_prepare().await
}

#[cfg(windows)]
async fn private_prepare() -> Result<(), nelomai_client_tunnel::TunnelError> {
    crate::runtime::native()
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common runtime unavailable".into())
        })?
        .control(crate::runtime::NativeControl::Prepare)
        .await
        .map(|_| ())
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common preparation failed".into())
        })
}
#[cfg(windows)]
pub async fn defender_status(
    refresh: bool,
) -> Result<nelomai_windows_service::DefenderStatus, nelomai_client_tunnel::TunnelError> {
    match crate::runtime::native()
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common runtime unavailable".into())
        })?
        .control(crate::runtime::NativeControl::DefenderStatus { refresh })
        .await
    {
        Ok(crate::runtime::NativeReply::Defender { status }) => Ok(status),
        _ => Err(nelomai_client_tunnel::TunnelError::Backend(
            "common defender status unavailable".into(),
        )),
    }
}
#[cfg(windows)]
pub async fn repair_defender_exclusion(
) -> Result<nelomai_windows_service::DefenderStatus, nelomai_client_tunnel::TunnelError> {
    match crate::runtime::native()
        .map_err(|_| {
            nelomai_client_tunnel::TunnelError::Backend("common runtime unavailable".into())
        })?
        .control(crate::runtime::NativeControl::DefenderRepair)
        .await
    {
        Ok(crate::runtime::NativeReply::Defender { status }) => Ok(status),
        _ => Err(nelomai_client_tunnel::TunnelError::Backend(
            "common defender repair failed".into(),
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn prepare_tunnel_for_stop(
    app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    prepare_tunnel(app).await
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub async fn prepare_tunnel_for_stop(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    Ok(())
}
