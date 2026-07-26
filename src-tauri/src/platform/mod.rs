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
pub fn tunnel_controller(_app: tauri::AppHandle<tauri::Wry>) -> PlatformTunnelController {
    windows::tunnel_controller()
}
