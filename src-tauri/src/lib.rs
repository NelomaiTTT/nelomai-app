#[cfg(desktop)]
mod automatic_diagnostics;
mod commands;
#[cfg(not(target_os = "android"))]
mod connection_intent;
mod connection_metrics;
#[cfg(desktop)]
mod desktop;
mod diagnostics;
#[cfg(desktop)]
mod network_incidents;
mod platform;
mod preferences;
mod resource_usage;
mod updates;

use nelomai_client_api::ClientApi;
use nelomai_client_application::{ApplicationError, ClientApplication};
use nelomai_client_container::{
    AuthBroker, InstalledRuntimeSelection, OwnerRuntimeAuth, RuntimeCacheAdmission,
    RuntimeClientProfile,
};
use nelomai_client_core::CoreLocalStop;
use nelomai_client_storage::{
    ContainerOwnerLock, ProtectedRuntimeStore, RuntimeOperationalStore, RuntimeRecordOwner,
    SystemRecordFactory, SystemSecretStore,
};
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
    RuntimeOperationalStore<ProtectedRuntimeStore<SystemSecretStore>>,
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
        #[cfg(target_os = "android")]
        if replay_push_cleanup(app).await.is_err() {
            return;
        }
        register_android_push(app, application).await;
    }

    #[cfg(any(target_os = "android", test))]
    async fn cleanup_push<F>(
        &self,
        broker: &AuthBroker,
        epoch: u64,
        disable: F,
    ) -> Result<bool, nelomai_client_container::BrokerError>
    where
        F: std::future::Future<Output = Result<(), nelomai_client_container::BrokerError>>,
    {
        let _guard = self.gate.lock().await;
        Self::cleanup_push_locked(broker, epoch, disable).await
    }

    /// Caller retains the push gate through native completion.
    #[cfg(any(target_os = "android", test))]
    async fn cleanup_push_locked<F>(
        broker: &AuthBroker,
        epoch: u64,
        disable: F,
    ) -> Result<bool, nelomai_client_container::BrokerError>
    where
        F: std::future::Future<Output = Result<(), nelomai_client_container::BrokerError>>,
    {
        if !broker.push_cleanup_is_current(epoch).await? {
            return Ok(false);
        }
        // Completion owns the gate, even when the caller no longer waits. A
        // newer prepare/confirm cannot overtake an in-flight native disable.
        disable.await?;
        broker.finish_push_cleanup(epoch).await?;
        Ok(true)
    }

    pub(crate) async fn register_token(
        &self,
        app: &tauri::AppHandle,
        application: &NativeApplication,
        token: &str,
    ) -> Result<(), ApplicationError> {
        let _guard = self.gate.lock().await;
        #[cfg(target_os = "android")]
        {
            replay_push_cleanup(app).await.map_err(|_| {
                ApplicationError::Core(nelomai_client_core::CoreError::AuthRecoveryRequired)
            })?;
            let scope = application.current_access_token().await?;
            application.register_push_token(token).await?;
            check_push_scope(application, &scope).await?;
            use tauri_plugin_push_android::PushAndroidExt;
            app.push_android().confirm_async(token).await.map_err(|_| {
                ApplicationError::Core(nelomai_client_core::CoreError::AuthRecoveryRequired)
            })
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = app;
            application.register_push_token(token).await
        }
    }

    pub(crate) async fn logout<F>(&self, owner_logout: F) -> Result<(), ApplicationError>
    where
        F: std::future::Future<Output = Result<(), ApplicationError>>,
    {
        // Never acquire the registration gate before owner cancellation.
        owner_logout.await
    }
}

#[cfg(target_os = "android")]
struct AndroidOwnerStop {
    app: tauri::AppHandle,
    local: Arc<CoreLocalStop<platform::PlatformTunnelController>>,
}
#[cfg(target_os = "android")]
#[async_trait::async_trait]
impl nelomai_client_container::LocalAuthStop for AndroidOwnerStop {
    async fn stop_local(&self) -> Result<(), nelomai_client_container::BrokerError> {
        nelomai_client_container::LocalAuthStop::stop_local(self.local.as_ref()).await
    }
    async fn prepare_revocation(
        &self,
        cancel_epoch: u64,
    ) -> Result<(), nelomai_client_container::BrokerError> {
        use tauri_plugin_tunnel_android::TunnelAndroidExt;
        // This is a genuine asynchronous mobile callback, not a blocking wait
        // wrapped in an async function. Native keeps cleanup proofs until ACK.
        self.app
            .tunnel_android()
            .prepare_owner_revocation(tauri_plugin_tunnel_android::BackgroundOwnerLogoutRequest {
                cancel_epoch,
            })
            .await
            .map_err(|_| nelomai_client_container::BrokerError::RecoveryRequired)?;
        use tauri::Manager;
        let broker = self.app.state::<Arc<AuthBroker>>().inner().clone();
        broker.stage_push_cleanup(cancel_epoch).await?;
        enqueue_push_cleanup(self.app.clone(), cancel_epoch);
        Ok(())
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
    let builder = builder
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build());

    let builder = builder.setup(|app| {
        use tauri::Manager;

        let app_data_directory = app.path().app_data_dir()?;
        // Before any secret read/init on every desktop platform (and Android
        // host process). The Windows plugin above is only an activation UX.
        let owner_lock = Arc::new(ContainerOwnerLock::try_acquire(&app_data_directory)?);
        use base64::Engine;
        let public_key = option_env!("NELOMAI_RELEASE_MANIFEST_PUBLIC_KEY_B64")
            .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
            .transpose()
            .map_err(|_| {
                std::io::Error::other("runtime_startup_blocked: invalid pinned manifest key")
            })?;
        let selection = InstalledRuntimeSelection::prepare(
            &app.path().resource_dir()?.join("runtime"),
            owner_lock.as_ref(),
            public_key.as_deref(),
            std::env::consts::OS,
            std::env::consts::ARCH,
        )?;
        #[cfg(target_os = "linux")]
        let fallback = Some(app_data_directory.join("credentials"));
        #[cfg(not(target_os = "linux"))]
        let fallback = None;

        let (selection, storage) = selection.prepare_runtime_storage(
            owner_lock.as_ref(),
            &SystemRecordFactory::new("primary", fallback),
        )?;

        let api = ClientApi::new(PANEL_BASE)
            .and_then(|api| api.with_app_version(&selection.target().container_version))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let resource_baseline = resource_usage::ResourceSnapshot::capture(app.handle());
        let diagnostics = Arc::new(diagnostics::AppDiagnostics::new(
            app.path().app_data_dir()?.join("diagnostics"),
            resource_baseline,
        )?);
        diagnostics.record_named("startup.rust.setup_ready", None, None, None);
        let tunnel = Arc::new(platform::tunnel_controller(app.handle().clone()));
        let preferences = Arc::new(preferences::AppPreferenceStore::open_runtime(
            &nelomai_client_storage::RuntimeStateStore::paths(&storage.runtime).preferences,
            &app_data_directory.join("preferences.json"),
        )?);
        let local = CoreLocalStop::new(tunnel.clone());
        #[cfg(target_os = "android")]
        let owner_stop = Arc::new(AndroidOwnerStop {
            app: app.handle().clone(),
            local: local.clone(),
        });
        #[cfg(not(target_os = "android"))]
        let owner_stop = local.clone();
        let broker = Arc::new(AuthBroker::new(
            api.clone(),
            Arc::new(storage.auth),
            owner_stop,
        )?);
        // Migration/full-writer ownership is consumed here; only the paired
        // field-merge views and narrow admission control survive into runtime.
        let record_owner = RuntimeRecordOwner::new(storage.runtime);
        let port = Arc::new(OwnerRuntimeAuth::new(
            broker.clone(),
            selection.target().clone(),
            RuntimeClientProfile {
                platform: commands::current_platform(),
                platform_version: None,
                architecture: std::env::consts::ARCH.into(),
            },
            Arc::new(RuntimeCacheAdmission::new(record_owner.clone())),
            local.runtime_writer_gates(),
        )?);
        if tauri::async_runtime::block_on(port.admit_empty_current()).is_err() {
            diagnostics.record_named("runtime.admission.recovery_required", None, None, None);
        }
        let application = Arc::new(ClientApplication::with_split_tunnel_store(
            Arc::new(api),
            Arc::new(record_owner.operational()),
            Arc::new(record_owner.split()),
            port.clone(),
            local,
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
        #[cfg(not(target_os = "android"))]
        let connection_intent = Arc::new(connection_intent::DesktopConnectionIntent::new(
            app.handle().clone(),
            application.clone(),
            diagnostics.clone(),
        ));
        app.manage(diagnostics.clone());
        app.manage(application.clone());
        app.manage(owner_lock);
        app.manage(broker);
        app.manage(port);
        app.manage(tunnel.clone());
        app.manage(split_tunnel_scheduler.clone());
        app.manage(push_registration_scheduler.clone());
        app.manage(preferences);
        app.manage(connection_metrics.clone());
        #[cfg(not(target_os = "android"))]
        app.manage(connection_intent.clone());
        app.manage(Arc::new(updates::NativeUpdater::from_build(app.handle())?));
        #[cfg(desktop)]
        desktop::setup_tray(app)?;
        start_split_tunnel_scheduler(application.clone(), split_tunnel_scheduler);
        #[cfg(not(target_os = "android"))]
        start_physical_network_scheduler(application.clone(), connection_intent.clone());
        #[cfg(target_os = "android")]
        start_physical_network_scheduler(application.clone());
        start_pending_stop_scheduler(application.clone());
        #[cfg(not(target_os = "android"))]
        connection_intent.spawn();
        start_connection_metrics_scheduler(
            app.handle().clone(),
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
            commands::app_set_tic_egress_mode,
            commands::app_login,
            commands::app_bootstrap,
            commands::app_peer_options,
            commands::app_bind_peer,
            commands::app_unbind_peer,
            commands::app_refresh_probes,
            commands::app_prepare_tunnel,
            commands::app_windows_defender_status,
            commands::app_windows_defender_repair,
            commands::app_queue_start_failure_diagnostics,
            commands::app_start,
            commands::app_start_saved_stray,
            commands::app_stop,
            commands::app_wake_connection_intent,
            commands::app_pin_stray,
            commands::app_unpin_stray,
            commands::app_send_diagnostics,
            commands::app_record_startup_stage,
            commands::app_update_status,
            commands::app_update_refresh,
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
        .on_window_event(|_window, _event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = _event {
                use tauri::Manager;

                let preferences = _window.state::<Arc<preferences::AppPreferenceStore>>();
                if preferences.get().close_to_tray {
                    api.prevent_close();
                    desktop::hide_window(_window);
                } else {
                    api.prevent_close();
                    desktop::quit_application(_window.app_handle().clone());
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
    if application.current_access_token().await.is_err() {
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
        Err(error) => {
            let _ = diagnostics.automatic_upload_failed(current_unix_time());
            diagnostics.record_named(
                "diagnostics.automatic_upload_failed",
                candidate.report.tunnel_session_id.as_deref(),
                None,
                Some(&automatic_upload_error_code(&error)),
            );
        }
    }
    true
}

#[cfg(desktop)]
fn automatic_upload_error_code(error: &ApplicationError) -> String {
    use nelomai_client_core::{CoreApiError, CoreError};

    fn api_code(error: &CoreApiError) -> String {
        match error {
            CoreApiError::Unauthorized => "signed_out".to_string(),
            CoreApiError::AccessExpired => "access_expired".to_string(),
            CoreApiError::Retryable => "temporary_network_error".to_string(),
            CoreApiError::Rejected { code, .. } => code.clone(),
        }
    }

    match error {
        ApplicationError::Storage => "storage_unavailable".to_string(),
        ApplicationError::Clock => "clock_unavailable".to_string(),
        ApplicationError::Api(error) => api_code(error),
        ApplicationError::Core(error) => match error {
            CoreError::AuthenticationOutcomeUnknown => "authentication_outcome_unknown".to_string(),
            CoreError::AuthRecoveryRequired => "auth_recovery_required".to_string(),
            CoreError::SignedOut => "signed_out".to_string(),
            CoreError::AccessExpired => "access_expired".to_string(),
            CoreError::UpdateRequired => "update_required".to_string(),
            CoreError::SavedConnectionUnavailable => "saved_connection_unavailable".to_string(),
            CoreError::StartCancelled => "connection_intent_cancelled".to_string(),
            CoreError::Storage => "storage_unavailable".to_string(),
            CoreError::Api(error) => api_code(error),
            CoreError::Tunnel(code) | CoreError::SplitTunnel(code) => code.clone(),
        },
    }
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
            if application.current_access_token().await.is_ok() {
                let _ = scheduler.synchronize(&application, false).await;
            }
        }
    });
}

#[cfg(target_os = "android")]
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

#[cfg(not(target_os = "android"))]
fn start_physical_network_scheduler(
    application: Arc<NativeApplication>,
    connection_intent: Arc<connection_intent::DesktopConnectionIntent>,
) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(PHYSICAL_NETWORK_POLL_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if matches!(
                application.poll_physical_network(current_unix_time()).await,
                Ok(nelomai_client_core::PhysicalNetworkPollOutcome::Reconnected)
            ) {
                connection_intent.wake_for_network_change().await;
            }
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
    _app: tauri::AppHandle,
    application: Arc<NativeApplication>,
    tunnel: Arc<platform::PlatformTunnelController>,
    tracker: Arc<connection_metrics::ConnectionMetricsTracker>,
    diagnostics: Arc<diagnostics::AppDiagnostics>,
) {
    use nelomai_client_tunnel::TunnelController;

    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(CONNECTION_METRICS_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failure_recorded = false;
        let mut last_diagnostics_at: Option<std::time::Instant> = None;
        let mut last_diagnostics_session: Option<String> = None;
        let mut last_diagnostics_sample = None;
        let mut last_incident_sample = None;
        let mut skipped_probe_session: Option<String> = None;
        #[cfg(any(target_os = "macos", windows))]
        let mut stall_recovery_limiter = connection_metrics::StallRecoveryLimiter::default();
        #[cfg(target_os = "macos")]
        let mut macos_stall_recovery = MacosStallRecoveryEpisode::default();
        #[cfg(windows)]
        let mut windows_service_recovery = WindowsServiceRecoveryEpisode::default();
        loop {
            interval.tick().await;
            let Some(context) = application.connection_metrics_context().await else {
                tracker.clear().await;
                failure_recorded = false;
                last_diagnostics_at = None;
                last_diagnostics_session = None;
                last_diagnostics_sample = None;
                last_incident_sample = None;
                skipped_probe_session = None;
                #[cfg(any(target_os = "macos", windows))]
                stall_recovery_limiter.reset();
                #[cfg(target_os = "macos")]
                macos_stall_recovery.reset();
                #[cfg(windows)]
                windows_service_recovery.reset();
                continue;
            };
            let observed = tracker.is_observed().await;
            let endpoint_route_guard =
                cfg!(windows) && context.layer == nelomai_contracts::Layer::Stray;
            let incident_sampling = cfg!(desktop);
            let new_diagnostics_session =
                last_diagnostics_session.as_deref() != Some(context.session_id.as_str());
            let diagnostics_now = std::time::Instant::now();
            let diagnostics_due = connection_diagnostics_due(
                last_diagnostics_session.as_deref(),
                &context.session_id,
                last_diagnostics_at,
                diagnostics_now,
            );
            if !connection_metrics_poll_required(
                observed,
                diagnostics_due,
                endpoint_route_guard,
                incident_sampling,
            ) {
                continue;
            }
            if new_diagnostics_session {
                last_diagnostics_sample = None;
                last_incident_sample = None;
                failure_recorded = false;
                #[cfg(any(target_os = "macos", windows))]
                stall_recovery_limiter.reset();
                #[cfg(target_os = "macos")]
                macos_stall_recovery.reset();
                #[cfg(windows)]
                windows_service_recovery.reset();
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
            let collect_probe_target =
                cfg!(target_os = "macos") && context.layer == nelomai_contracts::Layer::Stray;
            match tunnel.metrics(collect_probe_target).await {
                Ok(Some(sample)) => {
                    failure_recorded = false;
                    #[cfg(windows)]
                    windows_service_recovery.reset();
                    #[cfg(target_os = "macos")]
                    let (sample, direct_probe_target) = {
                        let mut sample = sample;
                        let direct_probe_target = take_direct_probe_target(&mut sample);
                        (sample, direct_probe_target)
                    };
                    let incident_observation = diagnostics.observe_tunnel_metrics(
                        &context.session_id,
                        &sample,
                        last_incident_sample.as_ref(),
                    );
                    #[cfg(not(target_os = "macos"))]
                    let _ = incident_observation;
                    last_incident_sample = Some(sample.clone());
                    #[cfg(target_os = "macos")]
                    if context.layer == nelomai_contracts::Layer::Stray {
                        if let Some(observation) = incident_observation {
                            if macos_stall_recovery.should_attempt(
                                &context.session_id,
                                observation,
                                current_unix_time(),
                            ) {
                                let result = diagnose_and_recover_macos_stall(
                                    &_app,
                                    application.as_ref(),
                                    diagnostics.as_ref(),
                                    &context,
                                    direct_probe_target,
                                    &mut stall_recovery_limiter,
                                    macos_stall_recovery.allows_uncertain_recovery(),
                                )
                                .await;
                                macos_stall_recovery.complete(result, current_unix_time());
                            }
                        }
                    } else {
                        macos_stall_recovery.reset();
                    }
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
                    #[cfg(windows)]
                    {
                        let recovery_relevant = should_attempt_windows_service_recovery(
                            &error,
                            windows_service_recovery.is_active(),
                        );
                        let recovery_now = current_unix_time();
                        if windows_service_recovery.should_poll(recovery_relevant, recovery_now) {
                            let first_outage = windows_service_recovery.first_outage();
                            let pending = recover_windows_service_outage(
                                application.as_ref(),
                                tunnel.as_ref(),
                                diagnostics.as_ref(),
                                &context,
                                &mut stall_recovery_limiter,
                                first_outage,
                            )
                            .await;
                            windows_service_recovery.complete(pending, recovery_now);
                        } else if !recovery_relevant {
                            windows_service_recovery.reset();
                        }
                    }
                }
            }
        }
    });
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopStallClassification {
    TunnelPathFailed,
    PhysicalPathFailed,
    RecoveredBeforeProbe,
    Ambiguous,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosStallRecoveryResult {
    Complete,
    Retry,
    RetryAt(i64),
    DirectProbeUnavailable,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
struct MacosStallRecoveryEpisode {
    lease_id: String,
    pending: bool,
    retry_count: u8,
    direct_probe_failures: u8,
    next_attempt_at_unix: Option<i64>,
}

#[cfg(any(target_os = "macos", test))]
impl MacosStallRecoveryEpisode {
    fn should_attempt(
        &mut self,
        lease_id: &str,
        observation: diagnostics::TunnelMetricsObservation,
        now_unix: i64,
    ) -> bool {
        if self.lease_id != lease_id {
            self.reset();
            self.lease_id = lease_id.to_string();
        }
        match observation {
            diagnostics::TunnelMetricsObservation::Detected => {
                self.pending = true;
                self.retry_count = 0;
                self.direct_probe_failures = 0;
                self.next_attempt_at_unix = None;
                true
            }
            diagnostics::TunnelMetricsObservation::Recovered => {
                self.reset();
                false
            }
            diagnostics::TunnelMetricsObservation::Unchanged => {
                self.pending
                    && self
                        .next_attempt_at_unix
                        .is_none_or(|next_attempt| now_unix >= next_attempt)
            }
        }
    }

    fn allows_uncertain_recovery(&self) -> bool {
        self.direct_probe_failures > 0
    }

    fn complete(&mut self, result: MacosStallRecoveryResult, now_unix: i64) {
        match result {
            MacosStallRecoveryResult::Complete => {
                self.pending = false;
                self.retry_count = 0;
                self.direct_probe_failures = 0;
                self.next_attempt_at_unix = None;
            }
            MacosStallRecoveryResult::Retry | MacosStallRecoveryResult::DirectProbeUnavailable => {
                self.pending = true;
                self.retry_count = self.retry_count.saturating_add(1);
                if result == MacosStallRecoveryResult::DirectProbeUnavailable {
                    self.direct_probe_failures = self.direct_probe_failures.saturating_add(1);
                }
                let delay_seconds = match self.retry_count {
                    1 => 5,
                    2 => 15,
                    _ => 60,
                };
                self.next_attempt_at_unix = Some(now_unix.saturating_add(delay_seconds));
            }
            MacosStallRecoveryResult::RetryAt(next_attempt_at_unix) => {
                self.pending = true;
                self.next_attempt_at_unix = Some(next_attempt_at_unix);
            }
        }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsServiceRecoveryDecision {
    Wait,
    NoAction,
    RestartLocalTunnel,
}

#[cfg(any(windows, test))]
fn is_windows_service_outage(error: &nelomai_client_tunnel::TunnelError) -> bool {
    matches!(
        error,
        nelomai_client_tunnel::TunnelError::Backend(code)
            if matches!(code.as_str(), "service_unavailable" | "service_timeout")
    )
}

#[cfg(any(windows, test))]
fn should_attempt_windows_service_recovery(
    error: &nelomai_client_tunnel::TunnelError,
    episode_active: bool,
) -> bool {
    is_windows_service_outage(error)
        || matches!(
            error,
            nelomai_client_tunnel::TunnelError::Backend(code)
                if matches!(code.as_str(), "endpoint_route_lost" | "endpoint_route_unavailable")
        )
        || episode_active
}

#[cfg(any(windows, test))]
fn classify_windows_service_recovery(
    status: Option<nelomai_client_tunnel::TunnelStatus>,
) -> WindowsServiceRecoveryDecision {
    use nelomai_client_tunnel::TunnelStatus;

    match status {
        Some(TunnelStatus::Stopped | TunnelStatus::Failed) => {
            WindowsServiceRecoveryDecision::RestartLocalTunnel
        }
        Some(TunnelStatus::Running) => WindowsServiceRecoveryDecision::NoAction,
        Some(TunnelStatus::Starting | TunnelStatus::Stopping) | None => {
            WindowsServiceRecoveryDecision::Wait
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsLocalRestartOutcomeDecision {
    code: &'static str,
    refund_attempt: bool,
    retry_immediately: bool,
}

#[cfg(any(windows, test))]
fn classify_windows_local_restart_outcome(
    outcome: nelomai_client_core::StalledDataPlaneRecoveryOutcome,
) -> WindowsLocalRestartOutcomeDecision {
    use nelomai_client_core::StalledDataPlaneRecoveryOutcome;

    match outcome {
        StalledDataPlaneRecoveryOutcome::Busy => WindowsLocalRestartOutcomeDecision {
            code: "busy",
            refund_attempt: true,
            retry_immediately: false,
        },
        StalledDataPlaneRecoveryOutcome::Skipped => WindowsLocalRestartOutcomeDecision {
            code: "connection_changed",
            refund_attempt: true,
            retry_immediately: false,
        },
        StalledDataPlaneRecoveryOutcome::Unsupported => WindowsLocalRestartOutcomeDecision {
            code: "unsupported",
            refund_attempt: false,
            retry_immediately: false,
        },
        StalledDataPlaneRecoveryOutcome::Rebound => WindowsLocalRestartOutcomeDecision {
            code: "unexpected_rebound",
            refund_attempt: false,
            retry_immediately: false,
        },
        StalledDataPlaneRecoveryOutcome::Reconnected => WindowsLocalRestartOutcomeDecision {
            code: "reconnected",
            refund_attempt: false,
            retry_immediately: false,
        },
    }
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct WindowsServiceRecoveryEpisode {
    pending: bool,
    next_poll_at_unix: Option<i64>,
}

#[cfg(any(windows, test))]
impl WindowsServiceRecoveryEpisode {
    fn is_active(&self) -> bool {
        self.pending || self.next_poll_at_unix.is_some()
    }

    fn should_poll(&self, service_outage: bool, now_unix: i64) -> bool {
        service_outage
            && (self.pending
                || self
                    .next_poll_at_unix
                    .is_none_or(|next_poll| now_unix >= next_poll))
    }

    fn first_outage(&self) -> bool {
        !self.pending && self.next_poll_at_unix.is_none()
    }

    fn complete(&mut self, pending: bool, now_unix: i64) {
        self.pending = pending;
        self.next_poll_at_unix = (!pending).then(|| now_unix.saturating_add(10));
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(windows)]
async fn recover_windows_service_outage(
    application: &NativeApplication,
    tunnel: &platform::PlatformTunnelController,
    diagnostics: &diagnostics::AppDiagnostics,
    context: &nelomai_client_core::ConnectionMetricsContext,
    limiter: &mut connection_metrics::StallRecoveryLimiter,
    first_failure: bool,
) -> bool {
    use nelomai_client_core::{StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome};
    use nelomai_client_tunnel::TunnelController;

    let status = match tunnel.status().await {
        Ok(status) => Some(status),
        Err(error) => {
            if first_failure {
                diagnostics.record_named(
                    "windows.service.recovery_waiting",
                    Some(&context.session_id),
                    None,
                    Some(&error.to_string()),
                );
            }
            None
        }
    };
    match classify_windows_service_recovery(status) {
        WindowsServiceRecoveryDecision::Wait => true,
        WindowsServiceRecoveryDecision::NoAction => {
            if first_failure {
                diagnostics.record_named(
                    "windows.service.status_running_after_metrics_failure",
                    Some(&context.session_id),
                    None,
                    None,
                );
            }
            false
        }
        WindowsServiceRecoveryDecision::RestartLocalTunnel => {
            let attempt_unix = current_unix_time();
            if !limiter.begin_attempt(&context.session_id, attempt_unix) {
                diagnostics.record_named(
                    "windows.service.local_restart_skipped",
                    Some(&context.session_id),
                    None,
                    Some("rate_limited"),
                );
                return false;
            }
            match application
                .recover_stalled_data_plane(
                    &context.session_id,
                    StalledDataPlaneRecovery::RestartLocalTunnel,
                )
                .await
            {
                Ok(StalledDataPlaneRecoveryOutcome::Reconnected) => {
                    diagnostics.record_named(
                        "windows.service.local_tunnel_restarted",
                        Some(&context.session_id),
                        None,
                        None,
                    );
                    false
                }
                Ok(outcome) => {
                    let decision = classify_windows_local_restart_outcome(outcome);
                    if decision.refund_attempt {
                        limiter.cancel_attempt(&context.session_id, attempt_unix);
                    }
                    diagnostics.record_named(
                        "windows.service.local_restart_skipped",
                        Some(&context.session_id),
                        None,
                        Some(decision.code),
                    );
                    decision.retry_immediately
                }
                Err(error) => {
                    diagnostics.record_named(
                        "windows.service.local_restart_failed",
                        Some(&context.session_id),
                        None,
                        Some(&error.to_string()),
                    );
                    true
                }
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn classify_desktop_stall_probe(
    tunnel_probe_succeeded: bool,
    direct_probe_succeeded: Option<bool>,
) -> DesktopStallClassification {
    if tunnel_probe_succeeded {
        return DesktopStallClassification::RecoveredBeforeProbe;
    }
    match direct_probe_succeeded {
        Some(true) => DesktopStallClassification::TunnelPathFailed,
        Some(false) => DesktopStallClassification::PhysicalPathFailed,
        None => DesktopStallClassification::Ambiguous,
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MacosStallProbeAction {
    Complete,
    RetryProbe,
    Recover,
}

#[cfg(any(target_os = "macos", test))]
fn classify_macos_stall_recovery(
    classification: DesktopStallClassification,
    allow_uncertain_recovery: bool,
) -> MacosStallProbeAction {
    match classification {
        DesktopStallClassification::RecoveredBeforeProbe => MacosStallProbeAction::Complete,
        DesktopStallClassification::TunnelPathFailed => MacosStallProbeAction::Recover,
        DesktopStallClassification::PhysicalPathFailed | DesktopStallClassification::Ambiguous
            if allow_uncertain_recovery =>
        {
            MacosStallProbeAction::Recover
        }
        DesktopStallClassification::PhysicalPathFailed | DesktopStallClassification::Ambiguous => {
            MacosStallProbeAction::RetryProbe
        }
    }
}

#[cfg(target_os = "macos")]
fn take_direct_probe_target(
    sample: &mut nelomai_client_tunnel::TunnelMetrics,
) -> Option<std::net::IpAddr> {
    sample.probe_target.take()?.parse().ok()
}

#[cfg(target_os = "macos")]
async fn diagnose_and_recover_macos_stall(
    app: &tauri::AppHandle,
    application: &NativeApplication,
    diagnostics: &diagnostics::AppDiagnostics,
    context: &nelomai_client_core::ConnectionMetricsContext,
    direct_probe_target: Option<std::net::IpAddr>,
    limiter: &mut connection_metrics::StallRecoveryLimiter,
    allow_uncertain_recovery: bool,
) -> MacosStallRecoveryResult {
    use nelomai_client_core::{StalledDataPlaneRecovery, StalledDataPlaneRecoveryOutcome};

    let tunnel_probe_url = format!("{PANEL_BASE}/health");
    let tunnel_probe = application.probe_fresh_connection_latency_ms(&tunnel_probe_url);
    let direct_probe = async {
        match (context.probe_url.as_deref(), direct_probe_target) {
            (Some(url), Some(resolved_ip)) => Some(
                application
                    .probe_fresh_connection_latency_ms_resolved(url, resolved_ip)
                    .await
                    .is_some(),
            ),
            _ => None,
        }
    };
    let (tunnel_latency, direct_succeeded) = tokio::join!(tunnel_probe, direct_probe);
    let classification = classify_desktop_stall_probe(tunnel_latency.is_some(), direct_succeeded);
    let classification_code = match classification {
        DesktopStallClassification::TunnelPathFailed => "tunnel_path_failed_direct_ok",
        DesktopStallClassification::PhysicalPathFailed => "physical_path_failed",
        DesktopStallClassification::RecoveredBeforeProbe => "recovered_before_probe",
        DesktopStallClassification::Ambiguous => "ambiguous",
    };
    diagnostics.record_named(
        "tunnel.stall.classified",
        Some(&context.session_id),
        None,
        Some(classification_code),
    );
    match classify_macos_stall_recovery(classification, allow_uncertain_recovery) {
        MacosStallProbeAction::Complete => return MacosStallRecoveryResult::Complete,
        MacosStallProbeAction::RetryProbe => {
            return MacosStallRecoveryResult::DirectProbeUnavailable;
        }
        MacosStallProbeAction::Recover => {
            if classification != DesktopStallClassification::TunnelPathFailed {
                diagnostics.record_named(
                    "tunnel.stall.direct_probe_fallback",
                    Some(&context.session_id),
                    None,
                    Some(classification_code),
                );
            }
        }
    }
    {
        use tauri::Manager;

        let runtime = app
            .state::<Arc<connection_intent::DesktopConnectionIntent>>()
            .inner()
            .clone();
        if runtime.handle_stall(&context.session_id).await {
            return MacosStallRecoveryResult::Complete;
        }
    }
    let mut attempt_unix = current_unix_time();
    if !limiter.begin_attempt(&context.session_id, attempt_unix) {
        diagnostics.record_named(
            "tunnel.stall.recovery_skipped",
            Some(&context.session_id),
            None,
            Some("rate_limited"),
        );
        return MacosStallRecoveryResult::RetryAt(
            limiter
                .next_attempt_at_unix(&context.session_id)
                .unwrap_or_else(|| attempt_unix.saturating_add(60)),
        );
    }

    let rebind = application
        .recover_stalled_data_plane(&context.session_id, StalledDataPlaneRecovery::RebindUdp)
        .await;
    match rebind {
        Ok(StalledDataPlaneRecoveryOutcome::Rebound) => {
            diagnostics.record_named(
                "tunnel.stall.udp_rebound",
                Some(&context.session_id),
                None,
                None,
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
            if application
                .probe_fresh_connection_latency_ms(&tunnel_probe_url)
                .await
                .is_some()
            {
                diagnostics.record_named(
                    "tunnel.stall.recovered_after_rebind",
                    Some(&context.session_id),
                    None,
                    None,
                );
                return MacosStallRecoveryResult::Complete;
            }
        }
        Ok(StalledDataPlaneRecoveryOutcome::Busy) => {
            limiter.cancel_attempt(&context.session_id, attempt_unix);
            diagnostics.record_named(
                "tunnel.stall.recovery_skipped",
                Some(&context.session_id),
                None,
                Some("connection_busy"),
            );
            return MacosStallRecoveryResult::Retry;
        }
        Ok(StalledDataPlaneRecoveryOutcome::Skipped) => {
            limiter.cancel_attempt(&context.session_id, attempt_unix);
            diagnostics.record_named(
                "tunnel.stall.recovery_skipped",
                Some(&context.session_id),
                None,
                Some("connection_changed"),
            );
            return MacosStallRecoveryResult::Complete;
        }
        Ok(StalledDataPlaneRecoveryOutcome::Unsupported) => {
            diagnostics.record_named(
                "tunnel.stall.udp_rebind_unavailable",
                Some(&context.session_id),
                None,
                None,
            );
        }
        Ok(StalledDataPlaneRecoveryOutcome::Reconnected) => {
            return MacosStallRecoveryResult::Complete;
        }
        Err(error) => diagnostics.record_named(
            "tunnel.stall.udp_rebind_failed",
            Some(&context.session_id),
            None,
            Some(&error.to_string()),
        ),
    }

    for restart_attempt in 1..=2 {
        if restart_attempt > 1 {
            attempt_unix = current_unix_time();
            if !limiter.begin_attempt(&context.session_id, attempt_unix) {
                diagnostics.record_named(
                    "tunnel.stall.local_restart_retry_skipped",
                    Some(&context.session_id),
                    None,
                    Some("rate_limited"),
                );
                return MacosStallRecoveryResult::RetryAt(
                    limiter
                        .next_attempt_at_unix(&context.session_id)
                        .unwrap_or_else(|| attempt_unix.saturating_add(60)),
                );
            }
        }
        match application
            .recover_stalled_data_plane(
                &context.session_id,
                StalledDataPlaneRecovery::RestartLocalTunnel,
            )
            .await
        {
            Ok(StalledDataPlaneRecoveryOutcome::Reconnected) => {
                if application
                    .probe_fresh_connection_latency_ms(&tunnel_probe_url)
                    .await
                    .is_some()
                {
                    diagnostics.record_named(
                        "tunnel.stall.local_tunnel_restarted",
                        Some(&context.session_id),
                        None,
                        Some(if restart_attempt == 1 {
                            "verified_first_attempt"
                        } else {
                            "verified_retry"
                        }),
                    );
                    return MacosStallRecoveryResult::Complete;
                }
                diagnostics.record_named(
                    "tunnel.stall.local_restart_verification_failed",
                    Some(&context.session_id),
                    None,
                    Some(if restart_attempt == 1 {
                        "first_attempt"
                    } else {
                        "retry"
                    }),
                );
            }
            Ok(StalledDataPlaneRecoveryOutcome::Busy) => {
                limiter.cancel_attempt(&context.session_id, attempt_unix);
                diagnostics.record_named(
                    "tunnel.stall.local_restart_skipped",
                    Some(&context.session_id),
                    None,
                    Some("busy"),
                );
                return MacosStallRecoveryResult::Retry;
            }
            Ok(outcome) => {
                if outcome == StalledDataPlaneRecoveryOutcome::Skipped {
                    limiter.cancel_attempt(&context.session_id, attempt_unix);
                }
                diagnostics.record_named(
                    "tunnel.stall.local_restart_skipped",
                    Some(&context.session_id),
                    None,
                    Some(match outcome {
                        StalledDataPlaneRecoveryOutcome::Skipped => "connection_changed",
                        StalledDataPlaneRecoveryOutcome::Unsupported => "unsupported",
                        StalledDataPlaneRecoveryOutcome::Rebound => "unexpected_rebound",
                        StalledDataPlaneRecoveryOutcome::Busy
                        | StalledDataPlaneRecoveryOutcome::Reconnected => unreachable!(),
                    }),
                );
                return MacosStallRecoveryResult::Complete;
            }
            Err(error) => {
                diagnostics.record_named(
                    "tunnel.stall.local_restart_failed",
                    Some(&context.session_id),
                    None,
                    Some(&error.to_string()),
                );
                return MacosStallRecoveryResult::Retry;
            }
        }
    }
    MacosStallRecoveryResult::RetryAt(
        limiter
            .next_attempt_at_unix(&context.session_id)
            .unwrap_or_else(|| current_unix_time().saturating_add(60)),
    )
}

fn start_push_registration_scheduler(
    app: tauri::AppHandle,
    application: Arc<NativeApplication>,
    scheduler: Arc<PushRegistrationScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        // Replay a durable logout push marker on process startup, before any
        // new prepare. Periodic attempts also retain/retry it on native failure.
        scheduler.synchronize(&app, &application).await;
        let mut interval = tokio::time::interval(PUSH_REGISTRATION_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            scheduler.synchronize(&app, &application).await;
        }
    });
}

#[cfg(target_os = "android")]
fn enqueue_push_cleanup(app: tauri::AppHandle, epoch: u64) {
    use tauri::Manager;
    use tauri_plugin_push_android::PushAndroidExt;
    tauri::async_runtime::spawn(async move {
        let broker = app.state::<Arc<AuthBroker>>().inner().clone();
        let scheduler = app
            .state::<Arc<PushRegistrationScheduler>>()
            .inner()
            .clone();
        // No request timeout drops this completion owner or releases its gate.
        // Failure deliberately leaves the protected marker for startup replay.
        let _ = scheduler
            .cleanup_push(&broker, epoch, async {
                app.push_android()
                    .disable_async()
                    .await
                    .map_err(|_| nelomai_client_container::BrokerError::RecoveryRequired)
            })
            .await;
    });
}

/// Called only while the push scheduler gate is held.
#[cfg(target_os = "android")]
async fn replay_push_cleanup(
    app: &tauri::AppHandle,
) -> Result<(), nelomai_client_container::BrokerError> {
    use tauri::Manager;
    use tauri_plugin_push_android::PushAndroidExt;
    let broker = app.state::<Arc<AuthBroker>>().inner().clone();
    if let Some(epoch) = broker.pending_push_cleanup().await? {
        PushRegistrationScheduler::cleanup_push_locked(&broker, epoch, async {
            app.push_android()
                .disable_async()
                .await
                .map_err(|_| nelomai_client_container::BrokerError::RecoveryRequired)
        })
        .await?;
    }
    Ok(())
}

#[cfg(target_os = "android")]
async fn check_push_scope(
    application: &NativeApplication,
    scope: &nelomai_client_api::AccessSnapshot,
) -> Result<(), ApplicationError> {
    let current = application.current_access_token().await?;
    if current.auth_epoch() != scope.auth_epoch()
        || current.family() != scope.family()
        || current.identity() != scope.identity()
    {
        return Err(ApplicationError::Core(
            nelomai_client_core::CoreError::StartCancelled,
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
async fn register_android_push(app: &tauri::AppHandle, application: &NativeApplication) {
    use tauri_plugin_push_android::PushAndroidExt;

    let Ok(scope) = application.current_access_token().await else {
        return;
    };
    if let Ok(response) = app.push_android().prepare_async().await {
        if check_push_scope(application, &scope).await.is_err() {
            return;
        }
        if !response.permission_granted {
            let _ = application.unregister_push_token().await;
        } else if !response.token.trim().is_empty()
            && application
                .register_push_token(&response.token)
                .await
                .is_ok()
            && check_push_scope(application, &scope).await.is_ok()
        {
            let _ = app.push_android().confirm_async(&response.token).await;
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

fn connection_metrics_poll_required(
    observed: bool,
    diagnostics_due: bool,
    endpoint_route_guard: bool,
    incident_sampling: bool,
) -> bool {
    observed || diagnostics_due || endpoint_route_guard || incident_sampling
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct PushAuthMemory(std::sync::Mutex<Option<nelomai_client_storage::AuthStoreV1>>);
    impl nelomai_client_storage::AuthStore for PushAuthMemory {
        fn load(
            &self,
        ) -> Result<Option<nelomai_client_storage::AuthStoreV1>, nelomai_client_storage::StorageError>
        {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(
            &self,
            value: &nelomai_client_storage::AuthStoreV1,
        ) -> Result<(), nelomai_client_storage::StorageError> {
            *self.0.lock().unwrap() = Some(value.clone());
            Ok(())
        }
    }
    struct PushStop;
    #[async_trait::async_trait]
    impl nelomai_client_container::LocalAuthStop for PushStop {
        async fn stop_local(&self) -> Result<(), nelomai_client_container::BrokerError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct PushAuthRecord(Arc<std::sync::Mutex<Option<Vec<u8>>>>);
    impl nelomai_client_storage::ProtectedRecordStore for PushAuthRecord {
        fn load_record(&self) -> Result<Option<Vec<u8>>, nelomai_client_storage::StorageError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save_record(&self, bytes: &[u8]) -> Result<(), nelomai_client_storage::StorageError> {
            *self.0.lock().unwrap() = Some(bytes.to_vec());
            Ok(())
        }
        fn delete_record(&self) -> Result<(), nelomai_client_storage::StorageError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    struct PushLoginStop(std::sync::atomic::AtomicBool);
    #[async_trait::async_trait]
    impl nelomai_client_container::LocalAuthStop for PushLoginStop {
        async fn stop_local(&self) -> Result<(), nelomai_client_container::BrokerError> {
            if self.0.load(std::sync::atomic::Ordering::SeqCst) {
                Err(nelomai_client_container::BrokerError::RecoveryRequired)
            } else {
                Ok(())
            }
        }
    }

    async fn failed_login_push_replay(outcome: &str) {
        use nelomai_client_storage::{
            AuthStore, AuthStoreV1, LogoutState, ProtectedAuthStore, StoredAuth,
        };
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let local = outcome == "local";
        let unknown = outcome == "unknown";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            for (index, stream) in listener
                .incoming()
                .take(if local { 1 } else { 2 })
                .enumerate()
            {
                let mut stream = stream.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 16384);
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                stream.read_exact(&mut vec![0; length]).unwrap();
                let (status, body) = if index == 0 {
                    assert!(header.starts_with("POST /api/client/v1/auth/logout-runtime "));
                    (
                        "200 OK",
                        r#"{"code":"already_inactive","cleanup_reconcile_operation_id":"synthetic"}"#,
                    )
                } else {
                    assert!(header.starts_with("POST /api/client/v1/auth/login "));
                    if unknown {
                        ("502 Bad Gateway", "{}")
                    } else {
                        (
                            "401 Unauthorized",
                            r#"{"request_id":"synthetic","code":"invalid_credentials","message":"rejected"}"#,
                        )
                    }
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let record = PushAuthRecord::default();
        let store = Arc::new(ProtectedAuthStore::new(record.clone()));
        let mut auth = AuthStoreV1::from_legacy(&StoredAuth::new_install());
        auth.refresh_token = Some("synthetic-refresh".into());
        store.save(&auth).unwrap();
        let stop = Arc::new(PushLoginStop(AtomicBool::new(false)));
        let broker = AuthBroker::new(api.clone(), store.clone(), stop.clone()).unwrap();
        let mut pending = store.load().unwrap().unwrap();
        pending.auth_epoch = 1;
        pending.logout_state = LogoutState::Pending;
        pending.broker.as_mut().unwrap().pending_logout =
            Some(nelomai_client_storage::PendingLogoutV1 {
                operation_id: "synthetic-logout".into(),
                refresh_proof: "synthetic-refresh".into(),
            });
        store.save(&pending).unwrap();
        broker.stage_push_cleanup(1).await.unwrap();
        let scheduler = PushRegistrationScheduler::new();
        let busy = scheduler.gate.lock().await;
        broker.logout().await.unwrap();
        assert_eq!(
            store.load().unwrap().unwrap().logout_state,
            LogoutState::LoggedOut
        );
        stop.0.store(local, Ordering::SeqCst);
        assert!(broker
            .login(
                &nelomai_client_api::LoginRequest {
                    login: "synthetic".into(),
                    password: "synthetic".into(),
                    install_secret: "ignored".into(),
                    device_name: "test".into(),
                    platform: nelomai_contracts::Platform::Macos,
                    platform_version: None,
                    architecture: "aarch64".into(),
                    app_version: "0.2.16".into(),
                },
                &nelomai_client_api::RuntimeTarget {
                    container_version: "0.2.16".into(),
                    runtime_version: "0.2.16".into(),
                    runtime_contract_version: 1,
                    runtime_slot: nelomai_contracts::RuntimeSlot::Latest,
                },
            )
            .await
            .is_err());
        server.join().unwrap();
        let after_login = store.load().unwrap().unwrap();
        assert_eq!(after_login.auth_epoch, 2);
        assert_eq!(
            after_login.logout_state,
            if unknown {
                LogoutState::Active
            } else {
                LogoutState::LoggedOut
            }
        );
        assert_eq!(
            after_login
                .broker
                .as_ref()
                .unwrap()
                .authentication_outcome_unknown,
            unknown
        );
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(1));
        drop(busy);
        drop(scheduler);
        drop(broker);
        drop(store);
        let store = Arc::new(ProtectedAuthStore::new(record));
        let broker = AuthBroker::new(api, store.clone(), Arc::new(PushStop)).unwrap();
        let scheduler = PushRegistrationScheduler::new();
        let _gate = scheduler.gate.lock().await;
        let epoch = broker.pending_push_cleanup().await.unwrap().unwrap();
        let disables = AtomicUsize::new(0);
        assert!(
            PushRegistrationScheduler::cleanup_push_locked(&broker, epoch, async {
                disables.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap(),
            "{outcome}: durable cleanup was skipped on restart"
        );
        assert_eq!(disables.load(Ordering::SeqCst), 1);
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), None);
        let mut expected = after_login;
        expected.broker.as_mut().unwrap().pending_push_cleanup_epoch = None;
        assert_eq!(
            store.load().unwrap().unwrap(),
            expected,
            "cleanup cannot change login provenance"
        );
    }

    #[tokio::test]
    async fn rejected_login_push_cleanup_executes_after_restart() {
        failed_login_push_replay("rejected").await;
    }

    #[tokio::test]
    async fn locally_unissued_login_push_cleanup_executes_after_restart() {
        failed_login_push_replay("local").await;
    }

    #[tokio::test]
    async fn unknown_login_push_cleanup_executes_after_restart() {
        failed_login_push_replay("unknown").await;
    }

    #[tokio::test]
    async fn late_push_completion_cannot_clear_newer_logout_cleanup() {
        use nelomai_client_storage::{AuthStore, AuthStoreV1, LogoutState, StoredAuth};
        let store = Arc::new(PushAuthMemory::default());
        store
            .save(&AuthStoreV1::from_legacy(&StoredAuth::new_install()))
            .unwrap();
        let broker = Arc::new(
            AuthBroker::new(
                ClientApi::new("http://127.0.0.1:1").unwrap(),
                store.clone(),
                Arc::new(PushStop),
            )
            .unwrap(),
        );
        // Synthetic post-ACK record with a durable, unfinished native handoff.
        let mut auth = store.load().unwrap().unwrap();
        auth.auth_epoch = 1;
        auth.logout_state = LogoutState::LoggedOut;
        auth.broker.as_mut().unwrap().pending_push_cleanup_epoch = Some(1);
        store.save(&auth).unwrap();
        let scheduler = Arc::new(PushRegistrationScheduler::new());
        let (entered, seen) = tokio::sync::oneshot::channel();
        let (release, completion) = tokio::sync::oneshot::channel();
        let task = {
            let broker = broker.clone();
            let scheduler = scheduler.clone();
            tokio::spawn(async move {
                scheduler
                    .cleanup_push(&broker, 1, async {
                        entered.send(()).unwrap();
                        completion.await.unwrap();
                        Ok(())
                    })
                    .await
            })
        };
        seen.await.unwrap();
        broker.logout().await.unwrap();
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(2));
        assert!(scheduler.gate.try_lock().is_err());
        release.send(()).unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(nelomai_client_container::BrokerError::Cancelled)
        ));
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(2));
        assert!(!scheduler
            .cleanup_push(&broker, 1, async {
                panic!("superseded cleanup must not dispatch");
            })
            .await
            .unwrap());
        assert!(scheduler
            .cleanup_push(&broker, 2, async { Ok(()) })
            .await
            .unwrap());
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), None);
    }

    #[tokio::test]
    async fn busy_push_cleanup_skips_after_real_owner_login_and_holds_gate_until_completion() {
        use nelomai_client_storage::{AuthStore, AuthStoreV1, LogoutState, StoredAuth};
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                    assert!(header.len() < 16384);
                }
                let header = String::from_utf8(header).unwrap();
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                stream.read_exact(&mut vec![0; length]).unwrap();
                let body = if header.starts_with("POST /api/client/v1/auth/login ") {
                    r#"{"api_version":"1","request_id":"synthetic","token_type":"Bearer","access_token":"synthetic-access","access_expires_in":900,"refresh_token":"synthetic-refresh","refresh_expires_in":3600,"access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},"device":{"id":"device","name":"test","platform":"macos","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"latest","session_generation":8}}"#
                } else {
                    r#"{"code":"already_inactive","cleanup_reconcile_operation_id":"synthetic"}"#
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let store = Arc::new(PushAuthMemory::default());
        let mut auth = AuthStoreV1::from_legacy(&StoredAuth::new_install());
        auth.auth_epoch = 1;
        auth.logout_state = LogoutState::Active;
        auth.refresh_token = Some("synthetic-refresh".into());
        store.save(&auth).unwrap();
        let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(PushStop)).unwrap());
        // Synthetic saved handoff state, then the actual owner completes HTTP logout.
        let mut handoff = store.load().unwrap().unwrap();
        handoff.logout_state = LogoutState::Pending;
        handoff.broker.as_mut().unwrap().pending_logout =
            Some(nelomai_client_storage::PendingLogoutV1 {
                operation_id: "synthetic-logout".into(),
                refresh_proof: "synthetic-refresh".into(),
            });
        store.save(&handoff).unwrap();
        broker.stage_push_cleanup(1).await.unwrap();
        let scheduler = Arc::new(PushRegistrationScheduler::new());
        let busy = scheduler.gate.lock().await;
        let disables = Arc::new(AtomicUsize::new(0));
        let task = {
            let scheduler = scheduler.clone();
            let broker = broker.clone();
            let disables = disables.clone();
            tokio::spawn(async move {
                scheduler
                    .cleanup_push(&broker, 1, async {
                        disables.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            })
        };
        broker.logout().await.unwrap();
        broker
            .login(
                &nelomai_client_api::LoginRequest {
                    login: "synthetic".into(),
                    password: "synthetic".into(),
                    install_secret: "ignored".into(),
                    device_name: "test".into(),
                    platform: nelomai_contracts::Platform::Macos,
                    platform_version: None,
                    architecture: "aarch64".into(),
                    app_version: "0.2.16".into(),
                },
                &nelomai_client_api::RuntimeTarget {
                    container_version: "0.2.16".into(),
                    runtime_version: "0.2.16".into(),
                    runtime_contract_version: 1,
                    runtime_slot: nelomai_contracts::RuntimeSlot::Latest,
                },
            )
            .await
            .unwrap();
        drop(busy);
        assert!(!task.await.unwrap().unwrap());
        assert_eq!(disables.load(Ordering::SeqCst), 0);
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), None);
        server.join().unwrap();

        let mut pending = store.load().unwrap().unwrap();
        pending.logout_state = LogoutState::Pending;
        let epoch = pending.auth_epoch;
        store.save(&pending).unwrap();
        broker.stage_push_cleanup(epoch).await.unwrap();
        let (entered, seen) = tokio::sync::oneshot::channel();
        let (release, completion) = tokio::sync::oneshot::channel();
        let task = {
            let scheduler = scheduler.clone();
            let broker = broker.clone();
            tokio::spawn(async move {
                scheduler
                    .cleanup_push(&broker, epoch, async {
                        entered.send(()).unwrap();
                        completion.await.unwrap();
                        Ok(())
                    })
                    .await
            })
        };
        seen.await.unwrap();
        assert!(
            scheduler.gate.try_lock().is_err(),
            "new prepare cannot overtake a native disable still executing"
        );
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(epoch));
        release.send(()).unwrap();
        assert!(task.await.unwrap().unwrap());
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), None);
        broker.stage_push_cleanup(epoch).await.unwrap();
        assert!(scheduler
            .cleanup_push(&broker, epoch, async {
                Err(nelomai_client_container::BrokerError::Timeout)
            })
            .await
            .is_err());
        assert_eq!(broker.pending_push_cleanup().await.unwrap(), Some(epoch));
        drop(broker);
        drop(scheduler);
        let reopened = AuthBroker::new(
            ClientApi::new("http://127.0.0.1:1").unwrap(),
            store,
            Arc::new(PushStop),
        )
        .unwrap();
        let restarted = PushRegistrationScheduler::new();
        let gate = restarted.gate.lock().await;
        let replay = reopened.pending_push_cleanup().await.unwrap().unwrap();
        assert!(
            PushRegistrationScheduler::cleanup_push_locked(&reopened, replay, async { Ok(()) })
                .await
                .unwrap()
        );
        assert_eq!(reopened.pending_push_cleanup().await.unwrap(), None);
        drop(gate);
    }

    #[cfg(not(target_os = "android"))]
    #[tokio::test]
    async fn logout_enters_owner_while_push_scheduler_is_occupied() {
        let scheduler = PushRegistrationScheduler::new();
        let _old_push = scheduler.gate.lock().await;
        let result = tokio::time::timeout(
            Duration::from_millis(30),
            scheduler.logout(async {
                Err(ApplicationError::Core(
                    nelomai_client_core::CoreError::AuthRecoveryRequired,
                ))
            }),
        )
        .await
        .expect("push registration must not delay owner cancellation");
        assert!(matches!(
            result,
            Err(ApplicationError::Core(
                nelomai_client_core::CoreError::AuthRecoveryRequired
            ))
        ));
    }

    #[test]
    fn automatic_upload_diagnostics_preserves_the_stable_failure_reason() {
        assert_eq!(
            automatic_upload_error_code(&ApplicationError::Api(
                nelomai_client_core::CoreApiError::Retryable,
            )),
            "temporary_network_error",
        );
        assert_eq!(
            automatic_upload_error_code(&ApplicationError::Api(
                nelomai_client_core::CoreApiError::Rejected {
                    code: "diagnostics_rate_limited".to_string(),
                    message: "retry later".to_string(),
                    retry_after_seconds: None,
                },
            )),
            "diagnostics_rate_limited",
        );
    }

    #[test]
    fn desktop_incident_sampling_does_not_depend_on_visible_metrics() {
        assert!(connection_metrics_poll_required(false, false, false, true));
        assert!(!connection_metrics_poll_required(
            false, false, false, false
        ));
    }

    #[test]
    fn desktop_stall_recovery_requires_a_healthy_direct_path() {
        assert_eq!(
            classify_desktop_stall_probe(false, Some(true)),
            DesktopStallClassification::TunnelPathFailed,
        );
        assert_eq!(
            classify_desktop_stall_probe(false, Some(false)),
            DesktopStallClassification::PhysicalPathFailed,
        );
        assert_eq!(
            classify_desktop_stall_probe(true, Some(true)),
            DesktopStallClassification::RecoveredBeforeProbe,
        );
        assert_eq!(
            classify_desktop_stall_probe(false, None),
            DesktopStallClassification::Ambiguous,
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn endpoint_probe_target_is_consumed_before_metrics_are_recorded() {
        let mut sample = nelomai_client_tunnel::TunnelMetrics {
            probe_target: Some("192.0.2.10".to_string()),
            ..nelomai_client_tunnel::TunnelMetrics::default()
        };

        assert_eq!(
            take_direct_probe_target(&mut sample),
            Some("192.0.2.10".parse().unwrap()),
        );
        assert_eq!(sample.probe_target, None);
    }

    #[test]
    fn macos_open_stall_retries_until_metrics_recover() {
        use diagnostics::TunnelMetricsObservation;

        let mut episode = MacosStallRecoveryEpisode::default();
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Detected, 100));
        episode.complete(MacosStallRecoveryResult::Retry, 100);
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 104));
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 105));
        episode.complete(MacosStallRecoveryResult::Retry, 105);
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 119));
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 120));
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Recovered, 121));
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 200));
    }

    #[test]
    fn macos_open_stall_retries_a_failed_direct_probe_and_waits_for_the_limiter() {
        use diagnostics::TunnelMetricsObservation;

        let mut episode = MacosStallRecoveryEpisode::default();
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Detected, 100));
        assert!(!episode.allows_uncertain_recovery());

        episode.complete(MacosStallRecoveryResult::DirectProbeUnavailable, 100);
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 104));
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 105));
        assert!(episode.allows_uncertain_recovery());

        episode.complete(MacosStallRecoveryResult::RetryAt(700), 105);
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 699));
        assert!(episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 700));

        episode.complete(MacosStallRecoveryResult::Complete, 700);
        assert!(!episode.should_attempt("lease-a", TunnelMetricsObservation::Unchanged, 701));
    }

    #[test]
    fn macos_recovery_uses_a_second_failed_direct_probe_as_endpoint_migration_fallback() {
        assert_eq!(
            classify_macos_stall_recovery(DesktopStallClassification::PhysicalPathFailed, false),
            MacosStallProbeAction::RetryProbe,
        );
        assert_eq!(
            classify_macos_stall_recovery(DesktopStallClassification::PhysicalPathFailed, true),
            MacosStallProbeAction::Recover,
        );
        assert_eq!(
            classify_macos_stall_recovery(DesktopStallClassification::Ambiguous, true),
            MacosStallProbeAction::Recover,
        );
    }

    #[test]
    fn windows_service_recovery_only_handles_manager_outages() {
        use nelomai_client_tunnel::TunnelError;

        assert!(is_windows_service_outage(&TunnelError::Backend(
            "service_unavailable".to_string(),
        )));
        assert!(is_windows_service_outage(&TunnelError::Backend(
            "service_timeout".to_string(),
        )));
        assert!(!is_windows_service_outage(&TunnelError::Backend(
            "missing_tunnel_metrics".to_string(),
        )));
        assert!(!is_windows_service_outage(&TunnelError::InvalidOptions {
            code: "invalid_options",
        }));
    }

    #[test]
    fn windows_recovery_handles_terminal_endpoint_route_failures() {
        use nelomai_client_tunnel::TunnelError;

        assert!(should_attempt_windows_service_recovery(
            &TunnelError::Backend("endpoint_route_lost".to_string()),
            false,
        ));
        assert!(should_attempt_windows_service_recovery(
            &TunnelError::Backend("endpoint_route_unavailable".to_string()),
            false,
        ));
        assert!(!should_attempt_windows_service_recovery(
            &TunnelError::Backend("route_conflict".to_string()),
            false,
        ));
    }

    #[test]
    fn windows_service_recovery_waits_for_a_terminal_tunnel_state() {
        assert_eq!(
            classify_windows_service_recovery(None),
            WindowsServiceRecoveryDecision::Wait,
        );
        assert_eq!(
            classify_windows_service_recovery(Some(TunnelStatus::Starting)),
            WindowsServiceRecoveryDecision::Wait,
        );
        assert_eq!(
            classify_windows_service_recovery(Some(TunnelStatus::Stopping)),
            WindowsServiceRecoveryDecision::Wait,
        );
        assert_eq!(
            classify_windows_service_recovery(Some(TunnelStatus::Running)),
            WindowsServiceRecoveryDecision::NoAction,
        );
        assert_eq!(
            classify_windows_service_recovery(Some(TunnelStatus::Stopped)),
            WindowsServiceRecoveryDecision::RestartLocalTunnel,
        );
        assert_eq!(
            classify_windows_service_recovery(Some(TunnelStatus::Failed)),
            WindowsServiceRecoveryDecision::RestartLocalTunnel,
        );
    }

    #[test]
    fn windows_service_outage_has_an_independent_recovery_episode() {
        let mut episode = WindowsServiceRecoveryEpisode::default();
        assert!(!episode.is_active());
        assert!(episode.should_poll(true, 100));
        episode.complete(false, 100);
        assert!(episode.is_active());
        assert!(!episode.should_poll(true, 109));
        assert!(episode.should_poll(true, 110));
        episode.complete(true, 110);
        assert!(episode.should_poll(true, 111));
        assert!(!episode.should_poll(false, 111));
    }

    #[test]
    fn windows_service_outage_episode_resets_for_a_new_lease() {
        let mut episode = WindowsServiceRecoveryEpisode::default();
        assert!(episode.first_outage());
        episode.complete(false, 100);
        assert!(!episode.first_outage());
        assert!(!episode.should_poll(true, 101));

        episode.reset();
        assert!(episode.first_outage());
        assert!(episode.should_poll(true, 101));
    }

    #[test]
    fn windows_busy_local_restart_is_retried_after_the_poll_delay() {
        let decision = classify_windows_local_restart_outcome(
            nelomai_client_core::StalledDataPlaneRecoveryOutcome::Busy,
        );
        assert!(decision.refund_attempt);
        assert!(!decision.retry_immediately);

        let mut episode = WindowsServiceRecoveryEpisode::default();
        episode.complete(decision.retry_immediately, 100);
        assert!(!episode.should_poll(true, 109));
        assert!(episode.should_poll(true, 110));
    }

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
