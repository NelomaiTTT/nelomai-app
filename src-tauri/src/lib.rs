mod commands;
mod platform;

use nelomai_client_api::ClientApi;
use nelomai_client_application::ClientApplication;
use nelomai_client_core::NoopLogger;
use nelomai_client_storage::SystemSecretStore;
use std::sync::Arc;

const PANEL_BASE: &str = "https://nelomai.ru";

type NativeApplication =
    ClientApplication<ClientApi, SystemSecretStore, platform::PlatformTunnelController, NoopLogger>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_tunnel_android::init());

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    let builder = builder.setup(|app| {
        use tauri::Manager;

        #[cfg(desktop)]
        if let Ok(updater) =
            platform::updater::DesktopUpdateBackend::from_build(app.handle().clone())
        {
            app.manage(updater);
        }

        #[cfg(target_os = "linux")]
        let fallback = Some(app.path().app_data_dir()?.join("credentials"));
        #[cfg(not(target_os = "linux"))]
        let fallback = None;

        let api =
            ClientApi::new(PANEL_BASE).map_err(|error| std::io::Error::other(error.to_string()))?;
        let application = ClientApplication::new(
            Arc::new(api),
            Arc::new(SystemSecretStore::new("primary", fallback)),
            Arc::new(platform::tunnel_controller(app.handle().clone())),
            Arc::new(NoopLogger),
        );
        app.manage(Arc::new(application));
        Ok(())
    });

    builder
        .invoke_handler(tauri::generate_handler![
            commands::app_state,
            commands::app_login,
            commands::app_bootstrap,
            commands::app_peer_options,
            commands::app_bind_peer,
            commands::app_unbind_peer,
            commands::app_refresh_probes,
            commands::app_start,
            commands::app_start_saved_stray,
            commands::app_stop,
            commands::app_pin_stray,
            commands::app_unpin_stray,
            commands::app_logout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
