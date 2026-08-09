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
use tauri_plugin_tunnel_android::TunnelAndroidExt;
use tokio::sync::Mutex;

const PANEL_BASE: &str = "https://nelomai.ru";
const SPLIT_TUNNEL_POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const PHYSICAL_NETWORK_POLL_INTERVAL: Duration = Duration::from_secs(30);
const PENDING_STOP_RETRY_INTERVAL: Duration = Duration::from_secs(30);
const PUSH_REGISTRATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const CONNECTION_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(1);

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
    let builder = tauri::Builder::default();

    // Register this before every plugin that performs setup. A secondary
    // Windows launch must wake the existing window and exit before it can
    // create another tray icon or initialize a second application runtime.
    #[cfg(target_os = "windows")]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
        desktop::show_window(app);
    }));

    let builder = builder
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
        diagnostics.record_named("startup.rust.setup_ready", None, None, None);
        let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
        let preferences = Arc::new(preferences::AppPreferenceStore::new(
            app_data_directory.join("preferences.json"),
        ));
        let application = Arc::new(ClientApplication::with_split_tunnel_store(
            Arc::new(api),
            Arc::new(SystemSecretStore::new("primary", fallback)),
            Arc::new(FileSplitTunnelStore::new(&app_data_directory)),
            tunnel.clone(),
            diagnostics.clone(),
        ));
        let dns_servers = preferences.get().dns_provider.servers();
        application.set_dns_servers(dns_servers.clone());
        let app_handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            let _ = app_handle
                .tunnel_android()
                .update_quick_dns_async(tauri_plugin_tunnel_android::DnsServersRequest {
                    dns_servers: dns_servers.iter().map(ToString::to_string).collect(),
                })
                .await;
        });
        let split_tunnel_scheduler = Arc::new(SplitTunnelScheduler::new());
        let push_registration_scheduler = Arc::new(PushRegistrationScheduler::new());
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
        start_pending_stop_scheduler(application.clone());
        start_connection_metrics_scheduler(application.clone(), tunnel, connection_metrics);
        start_push_registration_scheduler(
            app.handle().clone(),
            application,
            push_registration_scheduler,
        );
        Ok(())
    });

    let app = builder
        .invoke_handler(tauri::generate_handler![
            commands::app_state,
            commands::app_preferences,
            commands::app_set_close_to_tray,
            commands::app_set_dns_provider,
            commands::app_login,
            commands::app_bootstrap,
            commands::app_peer_options,
            commands::app_bind_peer,
            commands::app_unbind_peer,
            commands::app_refresh_probes,
            commands::app_prepare_tunnel,
            commands::app_queue_start_failure_diagnostics,
            commands::app_start,
            commands::app_start_saved_stray,
            commands::app_stop,
            commands::app_pin_stray,
            commands::app_unpin_stray,
            commands::app_send_diagnostics,
            commands::app_record_startup_stage,
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
                    desktop::hide_window(window);
                } else {
                    api.prevent_close();
                    desktop::quit_application(window.app_handle().clone());
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|_app, _event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen { .. } = _event {
            desktop::show_window(_app);
        }
    });
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

fn start_pending_stop_scheduler(application: Arc<NativeApplication>) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(PENDING_STOP_RETRY_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = application.retry_pending_stop().await;
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
        let mut failure_recorded = false;
        loop {
            interval.tick().await;
            if !tracker.is_observed().await {
                tracker.clear().await;
                failure_recorded = false;
                continue;
            }
            let Some(context) = application.connection_metrics_context().await else {
                tracker.clear().await;
                failure_recorded = false;
                continue;
            };
            let probe = tracker.should_probe(&context.session_id).await;
            match tunnel.metrics(false).await {
                Ok(Some(sample)) => {
                    failure_recorded = false;
                    let probe_result = if probe {
                        if let Some(probe_url) = context.probe_url.as_deref() {
                            Some(
                                application
                                    .probe_connection_latency_ms(probe_url)
                                    .await
                                    .map(|latency| {
                                        latency.ceil().clamp(1.0, u32::MAX as f64) as u32
                                    }),
                            )
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    tracker
                        .record(&context.session_id, sample, probe_result)
                        .await;
                }
                Ok(None) => {
                    if !failure_recorded {
                        application.record_tunnel_unavailable(
                            "tunnel.metrics.unavailable",
                            "metrics_not_supported".to_string(),
                        );
                        failure_recorded = true;
                    }
                }
                Err(error) => {
                    if !failure_recorded {
                        application.record_tunnel_unavailable(
                            "tunnel.metrics.unavailable",
                            error.to_string(),
                        );
                        failure_recorded = true;
                    }
                }
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
