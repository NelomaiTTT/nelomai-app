mod commands;
mod connection_metrics;
#[cfg(desktop)]
mod desktop;
mod diagnostics;
mod platform;
mod preferences;
mod resource_usage;
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
const PUSH_REGISTRATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const CONNECTION_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(5);

type NativeApplication = ClientApplication<
    ClientApi,
    SystemSecretStore,
    platform::PlatformTunnelController,
    diagnostics::AppDiagnostics,
>;

pub(crate) struct SplitTunnelScheduler {
    gate: Mutex<()>,
}

pub(crate) struct PushRegistrationScheduler {
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

impl PushRegistrationScheduler {
    fn new() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }

    pub(crate) async fn synchronize(
        &self,
        app: &tauri::AppHandle,
        application: &NativeApplication,
    ) {
        let _guard = self.gate.lock().await;
        register_android_push(app, application).await;
    }

    pub(crate) async fn logout(
        &self,
        app: &tauri::AppHandle,
        application: &NativeApplication,
    ) -> Result<(), ApplicationError> {
        let _guard = self.gate.lock().await;
        #[cfg(target_os = "android")]
        {
            use tauri_plugin_push_android::PushAndroidExt;

            let _ = app.push_android().disable();
        }
        #[cfg(not(target_os = "android"))]
        let _ = app;
        application.logout().await
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
        .plugin(tauri_plugin_push_android::init())
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
        let resource_baseline = resource_usage::ResourceSnapshot::capture(app.handle());
        let diagnostics = Arc::new(diagnostics::AppDiagnostics::new(
            app.path().app_data_dir()?.join("diagnostics"),
            resource_baseline,
        )?);
        let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
        let application = Arc::new(ClientApplication::with_split_tunnel_store(
            Arc::new(api),
            Arc::new(SystemSecretStore::new("primary", fallback)),
            Arc::new(FileSplitTunnelStore::new(&app_data_directory)),
            tunnel.clone(),
            diagnostics.clone(),
        ));
        let split_tunnel_scheduler = Arc::new(SplitTunnelScheduler::new());
        let push_registration_scheduler = Arc::new(PushRegistrationScheduler::new());
        let preferences = Arc::new(preferences::AppPreferenceStore::new(
            app_data_directory.join("preferences.json"),
        ));
        let connection_metrics = Arc::new(connection_metrics::ConnectionMetricsTracker::new());
        app.manage(diagnostics);
        app.manage(application.clone());
        app.manage(split_tunnel_scheduler.clone());
        app.manage(push_registration_scheduler.clone());
        app.manage(preferences);
        app.manage(connection_metrics.clone());
        app.manage(Arc::new(updates::NativeUpdater::from_build(app.handle())?));
        #[cfg(desktop)]
        desktop::setup_tray(app)?;
        start_split_tunnel_scheduler(application.clone(), split_tunnel_scheduler);
        start_physical_network_scheduler(application.clone());
        start_connection_metrics_scheduler(application.clone(), tunnel, connection_metrics);
        start_push_registration_scheduler(
            app.handle().clone(),
            application,
            push_registration_scheduler,
        );
        Ok(())
    });

    builder
        .invoke_handler(tauri::generate_handler![
            commands::app_state,
            commands::app_preferences,
            commands::app_set_close_to_tray,
            commands::app_take_quick_action,
            commands::app_quick_toggle,
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
            commands::app_split_tunnel_add_address_rule,
            commands::app_split_tunnel_remove_address_rule,
            commands::app_notifications,
            commands::app_notification_read,
            commands::app_notifications_read_all,
            commands::app_register_push_token,
            commands::app_logout,
        ])
        .on_window_event(|window, event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                use tauri::Manager;

                let preferences = window.state::<Arc<preferences::AppPreferenceStore>>();
                if preferences.get().close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    api.prevent_close();
                    desktop::quit_application(window.app_handle().clone());
                }
            }
        })
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

fn start_connection_metrics_scheduler(
    application: Arc<NativeApplication>,
    tunnel: Arc<platform::PlatformTunnelController>,
    tracker: Arc<connection_metrics::ConnectionMetricsTracker>,
) {
    use nelomai_client_tunnel::TunnelController;

    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_METRICS_POLL_INTERVAL);
        loop {
            interval.tick().await;
            if !tracker.is_observed().await {
                tracker.clear().await;
                continue;
            }
            let state = application.state().await;
            let Some(connection) = state
                .connection
                .filter(|_| state.phase == nelomai_client_core::Phase::Connected)
            else {
                tracker.clear().await;
                continue;
            };
            let probe = tracker.should_probe(&connection.lease_id).await;
            if let Ok(Some(sample)) = tunnel.metrics(probe).await {
                let probe_result = if probe {
                    if let Some(target) = sample.probe_target.clone() {
                        tokio::task::spawn_blocking(move || {
                            nelomai_client_tunnel::probe_host(&target)
                        })
                        .await
                        .ok()
                    } else {
                        None
                    }
                } else {
                    None
                };
                tracker
                    .record(&connection.lease_id, sample, probe_result)
                    .await;
            }
        }
    });
}

fn start_push_registration_scheduler(
    app: tauri::AppHandle,
    application: Arc<NativeApplication>,
    scheduler: Arc<PushRegistrationScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(PUSH_REGISTRATION_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            scheduler.synchronize(&app, &application).await;
        }
    });
}

#[cfg(target_os = "android")]
async fn register_android_push(app: &tauri::AppHandle, application: &NativeApplication) {
    use tauri_plugin_push_android::PushAndroidExt;

    if application.current_access_token().is_err() {
        return;
    }
    if let Ok(response) = app.push_android().prepare() {
        if !response.permission_granted {
            let _ = application.unregister_push_token().await;
        } else if !response.token.trim().is_empty()
            && application
                .register_push_token(&response.token)
                .await
                .is_ok()
        {
            let _ = app.push_android().confirm(&response.token);
        }
    }
}

#[cfg(not(target_os = "android"))]
async fn register_android_push(_app: &tauri::AppHandle, _application: &NativeApplication) {}
