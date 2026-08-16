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
pub use unix::PlatformTunnelController;
#[cfg(windows)]
pub use windows::PlatformTunnelController;

#[cfg(target_os = "android")]
pub fn tunnel_controller(app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    tauri_plugin_tunnel_android::AndroidTunnelController::new(app)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn tunnel_controller(_app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    unix::tunnel_controller()
}

#[cfg(windows)]
pub async fn diagnostic_helper_log(tunnel: &PlatformTunnelController) -> Option<String> {
    let _ = tunnel;
    windows::diagnostic_helper_log().await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn diagnostic_helper_log(tunnel: &PlatformTunnelController) -> Option<String> {
    tunnel.diagnostics().await.ok()
}

#[cfg(windows)]
pub fn tunnel_controller(_app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    windows::tunnel_controller()
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
    unix::prepare_tunnel(app).await
}

#[cfg(windows)]
pub async fn prepare_tunnel(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    windows::prepare_tunnel().await
}

#[cfg(windows)]
pub async fn prepare_tunnel_for_stop(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    windows::prepare_tunnel().await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub async fn prepare_tunnel_for_stop(
    app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    unix::prepare_tunnel(app).await
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub async fn prepare_tunnel_for_stop(
    _app: tauri::AppHandle<tauri::Wry>,
) -> Result<(), nelomai_client_tunnel::TunnelError> {
    Ok(())
}
