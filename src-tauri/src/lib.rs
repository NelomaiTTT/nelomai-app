#[cfg(desktop)]
mod automatic_diagnostics;
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
const CONNECTION_DIAGNOSTICS_INTERVAL: Duration = Duration::from_secs(60);
#[cfg(desktop)]
const AUTOMATIC_DIAGNOSTICS_POLL_INTERVAL: Duration = Duration::from_secs(10);

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
        app.manage(diagnostics.clone());
        app.manage(application.clone());
        app.manage(tunnel.clone());
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
        start_connection_metrics_scheduler(
            application.clone(),
            tunnel.clone(),
            connection_metrics,
            diagnostics.clone(),
        );
        #[cfg(desktop)]
        start_automatic_diagnostics_scheduler(
            app.handle().clone(),
            application.clone(),
            tunnel.clone(),
            diagnostics,
        );
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

#[cfg(desktop)]
fn start_automatic_diagnostics_scheduler(
    app: tauri::AppHandle,
    application: Arc<NativeApplication>,
    tunnel: Arc<platform::PlatformTunnelController>,
    diagnostics: Arc<diagnostics::AppDiagnostics>,
) {
    use nelomai_client_tunnel::TunnelController;

    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(AUTOMATIC_DIAGNOSTICS_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let now = current_unix_time();
            let context = application.connection_metrics_context().await;
            let status = tunnel.status().await.ok();
            let (session_id, tunnel_may_be_running) = automatic_tunnel_state(
                context.as_ref().map(|context| context.session_id.as_str()),
                status,
            );
            let observation = match diagnostics.observe_automatic_tunnel(
                session_id,
                tunnel_may_be_running,
                now,
            ) {
                Ok(observation) => observation,
                Err(error) => {
                    diagnostics.record_named(
                        "diagnostics.automatic_observation_failed",
                        None,
                        None,
                        Some(&error.kind().to_string()),
                    );
                    continue;
                }
            };
            if observation.interval_started.is_some() {
                diagnostics.begin_automatic_resource_interval(
                    &observation,
                    resource_usage::ResourceSnapshot::capture(&app),
                );
            }

            match diagnostics.pending_automatic_seal() {
                Ok(Some(seal)) => {
                    let helper_log = platform::diagnostic_helper_log(&tunnel).await;
                    let resource_snapshot = resource_usage::ResourceSnapshot::capture(&app);
                    if let Err(error) = diagnostics.materialize_automatic_report(
                        &seal,
                        resource_snapshot,
                        helper_log,
                    ) {
                        diagnostics.record_named(
                            "diagnostics.automatic_report_queue_failed",
                            Some(&seal.session_id),
                            None,
                            Some(&error.kind().to_string()),
                        );
                        continue;
                    }
                    diagnostics.record_named(
                        "diagnostics.automatic_report_queued",
                        Some(&seal.session_id),
                        Some(&seal.report_id),
                        Some(&seal.trigger),
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    diagnostics.record_named(
                        "diagnostics.automatic_seal_read_failed",
                        None,
                        None,
                        Some(&error.kind().to_string()),
                    );
                    continue;
                }
            }

            upload_automatic_diagnostics_once(&application, &diagnostics).await;
        }
    });
}

#[cfg(desktop)]
fn automatic_tunnel_state(
    session_id: Option<&str>,
    status: Option<nelomai_client_tunnel::TunnelStatus>,
) -> (Option<&str>, bool) {
    use nelomai_client_tunnel::TunnelStatus;

    match status {
        Some(TunnelStatus::Stopped | TunnelStatus::Failed) => (None, false),
        Some(TunnelStatus::Starting | TunnelStatus::Running | TunnelStatus::Stopping) => {
            (session_id, true)
        }
        None => (session_id, true),
    }
}

#[cfg(desktop)]
pub(crate) async fn upload_automatic_diagnostics_once(
    application: &NativeApplication,
    diagnostics: &diagnostics::AppDiagnostics,
) {
    let _ = upload_automatic_diagnostics(application, diagnostics, false).await;
}

#[cfg(desktop)]
pub(crate) async fn upload_latest_automatic_diagnostics_for_logout(
    application: &NativeApplication,
    diagnostics: &diagnostics::AppDiagnostics,
) {
    for _ in 0..50 {
        if upload_automatic_diagnostics(application, diagnostics, true).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(desktop)]
async fn upload_automatic_diagnostics(
    application: &NativeApplication,
    diagnostics: &diagnostics::AppDiagnostics,
    latest: bool,
) -> bool {
    if application.current_access_token().is_err() {
        return false;
    }
    let now = current_unix_time();
    let candidate_result = if latest {
        diagnostics.automatic_latest_upload_candidate(now)
    } else {
        diagnostics.automatic_upload_candidate(now)
    };
    let candidate = match candidate_result {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return false,
        Err(error) => {
            diagnostics.record_named(
                "diagnostics.automatic_report_read_failed",
                None,
                None,
                Some(&error.kind().to_string()),
            );
            let _ = diagnostics.automatic_upload_failed(now);
            return true;
        }
    };
    let expected_report_id = candidate.report.report_id.clone();
    match application.upload_diagnostics(&candidate.report).await {
        Ok(response) if Some(response.report_id.as_str()) == expected_report_id.as_deref() => {
            match diagnostics.automatic_upload_succeeded(&candidate, current_unix_time()) {
                Ok(()) => diagnostics.record_named(
                    "diagnostics.automatic_report_uploaded",
                    candidate.report.tunnel_session_id.as_deref(),
                    Some(&response.request_id),
                    Some(candidate.report.trigger.as_str()),
                ),
                Err(error) => {
                    let _ = diagnostics.automatic_upload_failed(current_unix_time());
                    diagnostics.record_named(
                        "diagnostics.automatic_sent_archive_failed",
                        candidate.report.tunnel_session_id.as_deref(),
                        Some(&response.request_id),
                        Some(&error.kind().to_string()),
                    );
                }
            }
        }
        Ok(_) => {
            let _ = diagnostics.automatic_upload_failed(current_unix_time());
            diagnostics.record_named(
                "diagnostics.automatic_upload_failed",
                candidate.report.tunnel_session_id.as_deref(),
                None,
                Some("invalid_diagnostics_response"),
            );
        }
        Err(_) => {
            let _ = diagnostics.automatic_upload_failed(current_unix_time());
            diagnostics.record_named(
                "diagnostics.automatic_upload_failed",
                candidate.report.tunnel_session_id.as_deref(),
                None,
                Some("upload_failed"),
            );
        }
    }
    true
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
    diagnostics: Arc<diagnostics::AppDiagnostics>,
) {
    use nelomai_client_tunnel::TunnelController;

    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_METRICS_POLL_INTERVAL);
        let mut failure_recorded = false;
        let mut last_diagnostics_at: Option<std::time::Instant> = None;
        let mut last_diagnostics_session: Option<String> = None;
        let mut last_diagnostics_sample = None;
        let mut skipped_probe_session: Option<String> = None;
        loop {
            interval.tick().await;
            let Some(context) = application.connection_metrics_context().await else {
                tracker.clear().await;
                failure_recorded = false;
                last_diagnostics_at = None;
                last_diagnostics_session = None;
                last_diagnostics_sample = None;
                skipped_probe_session = None;
                continue;
            };
            let observed = tracker.is_observed().await;
            let endpoint_route_guard =
                cfg!(windows) && context.layer == nelomai_contracts::Layer::Stray;
            let new_diagnostics_session =
                last_diagnostics_session.as_deref() != Some(context.session_id.as_str());
            let diagnostics_now = std::time::Instant::now();
            let diagnostics_due = connection_diagnostics_due(
                last_diagnostics_session.as_deref(),
                &context.session_id,
                last_diagnostics_at,
                diagnostics_now,
            );
            if !observed && !diagnostics_due && !endpoint_route_guard {
                continue;
            }
            if new_diagnostics_session {
                last_diagnostics_sample = None;
            }
            if diagnostics_due {
                last_diagnostics_at = Some(diagnostics_now);
                last_diagnostics_session = Some(context.session_id.clone());
            }
            let probe = observed && tracker.should_probe(&context.session_id).await;
            if probe
                && cfg!(target_os = "android")
                && skipped_probe_session.as_deref() != Some(context.session_id.as_str())
            {
                diagnostics.record_named(
                    "tunnel.probe.skipped",
                    Some(&context.session_id),
                    None,
                    Some("app_process_bypasses_vpn"),
                );
                skipped_probe_session = Some(context.session_id.clone());
            }
            match tunnel.metrics(false).await {
                Ok(Some(sample)) => {
                    failure_recorded = false;
                    // Nelomai is deliberately excluded from Android's own VpnService, so an
                    // HTTP request from the app process cannot validate the tunnel there.
                    // Desktop probes use the panel rather than the VPN endpoint, whose host
                    // route is intentionally kept outside the tunnel.
                    let probe_result = if probe && !cfg!(target_os = "android") {
                        Some(
                            application
                                .probe_connection_latency_ms(&format!("{PANEL_BASE}/health"))
                                .await
                                .map(|latency| latency.ceil().clamp(1.0, u32::MAX as f64) as u32),
                        )
                    } else {
                        None
                    };
                    if diagnostics_due {
                        diagnostics.record_tunnel_metrics(
                            &context.session_id,
                            &sample,
                            last_diagnostics_sample.as_ref(),
                            probe_result,
                        );
                        last_diagnostics_sample = Some(sample.clone());
                    }
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

fn connection_diagnostics_due(
    previous_session: Option<&str>,
    current_session: &str,
    previous_attempt: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    previous_session != Some(current_session)
        || previous_attempt.is_none_or(|attempt| {
            now.checked_duration_since(attempt).unwrap_or_default()
                >= CONNECTION_DIAGNOSTICS_INTERVAL
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(desktop)]
    use nelomai_client_tunnel::TunnelStatus;

    #[test]
    fn background_diagnostics_throttle_failed_attempts() {
        let now = std::time::Instant::now();
        assert!(connection_diagnostics_due(None, "session", None, now));
        assert!(!connection_diagnostics_due(
            Some("session"),
            "session",
            Some(now),
            now + CONNECTION_DIAGNOSTICS_INTERVAL - std::time::Duration::from_secs(1),
        ));
        assert!(connection_diagnostics_due(
            Some("session"),
            "session",
            Some(now),
            now + CONNECTION_DIAGNOSTICS_INTERVAL,
        ));
        assert!(connection_diagnostics_due(
            Some("old-session"),
            "session",
            Some(now),
            now,
        ));
    }

    #[cfg(desktop)]
    #[test]
    fn stopped_native_tunnel_overrides_stale_connection_context() {
        assert_eq!(
            automatic_tunnel_state(Some("stale-session"), Some(TunnelStatus::Stopped)),
            (None, false)
        );
        assert_eq!(
            automatic_tunnel_state(Some("stale-session"), Some(TunnelStatus::Failed)),
            (None, false)
        );
    }

    #[cfg(desktop)]
    #[test]
    fn uncertain_native_status_does_not_create_a_false_stop() {
        assert_eq!(
            automatic_tunnel_state(Some("session"), Some(TunnelStatus::Running)),
            (Some("session"), true)
        );
        assert_eq!(
            automatic_tunnel_state(Some("session"), None),
            (Some("session"), true)
        );
    }
}
