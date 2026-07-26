#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
mod platform;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_tunnel_android::init());

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    #[cfg(desktop)]
    let builder = builder.setup(|app| {
        use tauri::Manager;

        if let Ok(updater) =
            platform::updater::DesktopUpdateBackend::from_build(app.handle().clone())
        {
            app.manage(updater);
        }
        Ok(())
    });

    #[cfg(windows)]
    let builder = builder.manage(platform::windows::tunnel_controller());

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let builder = builder.manage(platform::unix::tunnel_controller());

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
