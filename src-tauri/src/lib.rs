mod commands;
mod diagnostics;
mod platform;
mod updates;

use nelomai_client_api::ClientApi;
use nelomai_client_application::{ApplicationError, ClientApplication};
use nelomai_client_storage::{FileSplitTunnelStore, SystemSecretStore};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const PANEL_BASE: &str = "https://nelomai.ru";
const SPLIT_TUNNEL_POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const PHYSICAL_NETWORK_POLL_INTERVAL: Duration = Duration::from_secs(30);

type NativeApplication = ClientApplication<
    ClientApi,
    SystemSecretStore,
    platform::PlatformTunnelController,
    diagnostics::AppDiagnostics,
>;

pub(crate) struct SplitTunnelScheduler {
    gate: Mutex<()>,
}

impl SplitTunnelScheduler {
    fn new() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }

    pub(crate) async fn synchronize(
        &self,
        application: &NativeApplication,
        force_full: bool,
    ) -> Result<nelomai_client_core::SplitTunnelSyncOutcome, ApplicationError> {
        let _guard = self.gate.lock().await;
        application
            .synchronize_split_tunnel(current_unix_time(), force_full)
            .await
    }
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_tunnel_android::init())
        .plugin(tauri_plugin_updater_android::init());

    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    let builder = builder.setup(|app| {
        use tauri::Manager;

        let app_data_directory = app.path().app_data_dir()?;
        #[cfg(target_os = "linux")]
        let fallback = Some(app_data_directory.join("credentials"));
        #[cfg(not(target_os = "linux"))]
        let fallback = None;

        let api = ClientApi::new(PANEL_BASE)
            .and_then(|api| api.with_app_version(env!("CARGO_PKG_VERSION")))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let diagnostics = Arc::new(diagnostics::AppDiagnostics::new(
            app.path().app_data_dir()?.join("diagnostics"),
        )?);
        let application = Arc::new(ClientApplication::with_split_tunnel_store(
            Arc::new(api),
            Arc::new(SystemSecretStore::new("primary", fallback)),
            Arc::new(FileSplitTunnelStore::new(&app_data_directory)),
            Arc::new(platform::tunnel_controller(app.handle().clone())),
            diagnostics.clone(),
        ));
        let split_tunnel_scheduler = Arc::new(SplitTunnelScheduler::new());
        app.manage(diagnostics);
        app.manage(application.clone());
        app.manage(split_tunnel_scheduler.clone());
        app.manage(Arc::new(updates::NativeUpdater::from_build(app.handle())?));
        start_split_tunnel_scheduler(application.clone(), split_tunnel_scheduler);
        start_physical_network_scheduler(application);
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
            commands::app_prepare_tunnel,
            commands::app_start,
            commands::app_start_saved_stray,
            commands::app_stop,
            commands::app_pin_stray,
            commands::app_unpin_stray,
            commands::app_send_diagnostics,
            commands::app_update_status,
            commands::app_update_set_automatic,
            commands::app_update_install,
            commands::app_update_restart,
            commands::app_split_tunnel_state,
            commands::app_split_tunnel_installed_applications,
            commands::app_split_tunnel_save,
            commands::app_split_tunnel_refresh,
            commands::app_logout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn start_split_tunnel_scheduler(
    application: Arc<NativeApplication>,
    scheduler: Arc<SplitTunnelScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(SPLIT_TUNNEL_POLL_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if application.current_access_token().is_ok() {
                let _ = scheduler.synchronize(&application, false).await;
            }
        }
    });
}

fn start_physical_network_scheduler(application: Arc<NativeApplication>) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(PHYSICAL_NETWORK_POLL_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = application.poll_physical_network(current_unix_time()).await;
        }
    });
}
