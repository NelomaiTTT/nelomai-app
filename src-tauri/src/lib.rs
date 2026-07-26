#[cfg(windows)]
mod platform;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_tunnel_android::init());

    #[cfg(windows)]
    let builder = builder.manage(platform::windows::tunnel_controller());

    builder
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
