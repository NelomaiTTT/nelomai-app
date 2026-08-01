use crate::diagnostics::AppDiagnostics;
use crate::updates::{NativeUpdater, UpdateStatusResponse};
use crate::{
    preferences::AppPreferenceStore, NativeApplication, PushRegistrationScheduler,
    SplitTunnelScheduler,
};
use nelomai_client_api::DiagnosticUploadResponse;
use nelomai_client_application::{ApplicationError, LoginParameters};
use nelomai_client_core::{
    split_tunnel_active, ConnectOptions, CoreApiError, CoreError, CoreState, Phase,
    SplitTunnelContext,
};
use nelomai_client_tunnel::{TunnelCapabilities, TunnelPlatform};
use nelomai_contracts::{
    AppNotificationList, AppNotificationReadResponse, BindPeerRequest, Bootstrap, Connection,
    Layer, PeerBinding, PeerBindingResponse, PeerOptions, Platform, ProbeResults, RouteMode,
    SplitTunnelAddressRuleScope, SplitTunnelAddressRuleUpdate, SplitTunnelMode,
    SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};
use tauri_plugin_tunnel_android::TunnelAndroidExt;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    code: String,
    message: String,
}

impl From<ApplicationError> for CommandError {
    fn from(error: ApplicationError) -> Self {
        match error {
            ApplicationError::Storage => Self::new(
                "storage_unavailable",
                "Защищённое хранилище временно недоступно",
            ),
            ApplicationError::Clock => {
                Self::new("clock_unavailable", "Не удалось определить текущее время")
            }
            ApplicationError::Api(error) => Self::from_api(error),
            ApplicationError::Core(error) => Self::from_core(error),
        }
    }
}

impl CommandError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    fn from_api(error: CoreApiError) -> Self {
        match error {
            CoreApiError::Unauthorized => Self::new("signed_out", "Нужно снова войти в приложение"),
            CoreApiError::AccessExpired => Self::new("access_expired", "Срок доступа уже истёк"),
            CoreApiError::Retryable => {
                Self::new("temporarily_unavailable", "Не удалось связаться с панелью")
            }
            CoreApiError::Rejected { code, message } => Self::new(code, message),
        }
    }

    fn from_core(error: CoreError) -> Self {
        match error {
            CoreError::SignedOut => Self::new("signed_out", "Нужно снова войти в приложение"),
            CoreError::AccessExpired => Self::new("access_expired", "Срок доступа уже истёк"),
            CoreError::UpdateRequired => Self::new(
                "update_required",
                "Для продолжения необходимо обновить приложение",
            ),
            CoreError::SavedConnectionUnavailable => Self::new(
                "saved_connection_unavailable",
                "Сохранённое подключение сейчас недоступно",
            ),
            CoreError::Storage => Self::new(
                "storage_unavailable",
                "Защищённое хранилище временно недоступно",
            ),
            CoreError::Api(error) => Self::from_api(error),
            CoreError::Tunnel(code) => match code.as_str() {
                "service_unavailable" => Self::new(
                    "tunnel_service_unavailable",
                    "Служба подключения не установлена или не запущена. Переустановите приложение",
                ),
                "physical_network_monitor_unavailable" => Self::new(
                    "physical_network_monitor_unavailable",
                    "Не удалось отслеживать смену сети на устройстве",
                ),
                _ => Self::from_route_error(&code).unwrap_or_else(|| {
                    Self::new("tunnel_failed", "Не удалось изменить состояние подключения")
                }),
            },
            CoreError::SplitTunnel(code) => match code.as_str() {
                "split_tunnel_empty_include_selection" => Self::new(
                    "split_tunnel_empty_include_selection",
                    "Выберите хотя бы одно приложение для подключения через VPN",
                ),
                "split_tunnel_apply_failed" => Self::new(
                    "split_tunnel_apply_failed",
                    "Не удалось применить новые настройки. Предыдущее подключение восстановлено",
                ),
                "split_tunnel_stop_failed" => Self::new(
                    "split_tunnel_stop_failed",
                    "Не удалось остановить подключение для применения новых настроек. Повторите позже",
                ),
                "split_tunnel_rollback_failed" => Self::new(
                    "split_tunnel_rollback_failed",
                    "Не удалось восстановить подключение. Запустите его снова",
                ),
                "split_tunnel_address_rule_invalid" => Self::new(
                    "split_tunnel_address_rule_invalid",
                    "Укажите корректный IPv4-адрес, домен или HTTP(S)-ссылку",
                ),
                _ => Self::new(
                    "split_tunnel_policy_unavailable",
                    "Настройки split-tunnel временно недоступны",
                ),
            },
        }
    }

    fn from_tunnel(error: nelomai_client_tunnel::TunnelError) -> Self {
        let code = match error {
            nelomai_client_tunnel::TunnelError::Backend(code) => code,
            nelomai_client_tunnel::TunnelError::InvalidOptions { code } => code.to_string(),
        };
        match code.as_str() {
            "vpn_permission_denied" => Self::new(
                "vpn_permission_denied",
                "Без разрешения Android подключение невозможно",
            ),
            "tunnel_backend_unavailable" => Self::new(
                "tunnel_backend_unavailable",
                "Система подключения недоступна на этом устройстве",
            ),
            "service_unavailable"
            | "service_outdated"
            | "unauthorized_client"
            | "truncated_frame" => Self::new(
                "tunnel_service_unavailable",
                "Компоненты подключения не установлены или устарели. Переустановите приложение",
            ),
            "helper_install_cancelled" => {
                Self::new("helper_install_cancelled", "Настройка подключения отменена")
            }
            "helper_authorization_unavailable" => Self::new(
                "helper_authorization_unavailable",
                "Не удалось открыть системный запрос прав администратора",
            ),
            "helper_resources_unavailable" => Self::new(
                "helper_resources_unavailable",
                "В установленном приложении отсутствуют компоненты подключения",
            ),
            "physical_network_monitor_unavailable" => Self::new(
                "physical_network_monitor_unavailable",
                "Не удалось отслеживать смену сети на устройстве",
            ),
            _ => Self::from_route_error(&code).unwrap_or_else(|| {
                Self::new(
                    "tunnel_failed",
                    "Не удалось запустить подключение на устройстве",
                )
            }),
        }
    }

    fn from_route_error(code: &str) -> Option<Self> {
        let message = match code {
            "route_conflict" => {
                "Не удалось применить split-tunnel: на устройстве уже существует такой маршрут"
            }
            "route_plan_too_large" | "route_state_too_large" => {
                "Список адресов split-tunnel слишком большой"
            }
            "physical_egress_unavailable" => {
                "Не удалось определить текущее подключение устройства к сети"
            }
            "local_networks_unavailable" => "Не удалось определить локальные сети этого устройства",
            "route_state_invalid"
            | "route_state_read_failed"
            | "route_state_write_failed"
            | "route_state_serialize_failed"
            | "route_state_activate_failed"
            | "route_state_remove_failed"
            | "route_add_failed"
            | "route_del_failed"
            | "route_delete_failed"
            | "route_command_failed"
            | "route_command_unavailable"
            | "route_table_unavailable"
            | "ip_command_unavailable" => "Не удалось применить маршруты split-tunnel",
            _ => return None,
        };
        Some(Self::new(code, message))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateResponse {
    phase: &'static str,
    connection: Option<Connection>,
    warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPreferencesResponse {
    close_to_tray_supported: bool,
    close_to_tray: bool,
}

impl AppStateResponse {
    fn new(state: CoreState, warning: Option<String>) -> Self {
        Self {
            phase: phase_name(state.phase),
            connection: state.connection,
            warning,
        }
    }
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::SignedOut => "signed_out",
        Phase::Authenticating => "authenticating",
        Phase::NeedsPeerBinding => "needs_peer_binding",
        Phase::AccessExpired => "access_expired",
        Phase::Ready => "ready",
        Phase::Measuring => "measuring",
        Phase::Connecting => "connecting",
        Phase::Connected => "connected",
        Phase::Stopping => "stopping",
        Phase::UpdateRequired => "update_required",
        Phase::ServerUnavailable => "server_unavailable",
        Phase::Error => "error",
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginCommandRequest {
    login: String,
    password: String,
    device_name: String,
    platform_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartCommandRequest {
    layer: Layer,
    tic_connection_mode: TicConnectionMode,
    route_mode: RouteMode,
    #[serde(default = "default_true")]
    allow_alternate: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseCommandRequest {
    lease_id: String,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafePeerBindingResponse {
    api_version: nelomai_contracts::ApiVersion,
    request_id: String,
    binding: Option<PeerBinding>,
}

impl From<PeerBindingResponse> for SafePeerBindingResponse {
    fn from(response: PeerBindingResponse) -> Self {
        Self {
            api_version: response.api_version,
            request_id: response.request_id,
            binding: response.binding,
        }
    }
}

#[tauri::command]
pub async fn app_state(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<AppStateResponse, CommandError> {
    let state = application.state().await;
    let warning = application.split_tunnel_warning().await;
    Ok(AppStateResponse::new(state, warning))
}

#[tauri::command]
pub fn app_preferences(preferences: State<'_, Arc<AppPreferenceStore>>) -> AppPreferencesResponse {
    AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: preferences.get().close_to_tray,
    }
}

#[tauri::command]
pub fn app_set_close_to_tray(
    preferences: State<'_, Arc<AppPreferenceStore>>,
    enabled: bool,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences.set_close_to_tray(enabled).map_err(|_| {
        CommandError::new(
            "preferences_unavailable",
            "Не удалось сохранить настройки приложения",
        )
    })?;
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
    })
}

#[tauri::command]
pub fn app_take_quick_action(app: AppHandle) -> Result<bool, CommandError> {
    app.tunnel_android()
        .take_quick_action()
        .map_err(|_| CommandError::new("quick_action_unavailable", "Не удалось открыть действие"))
}

#[tauri::command]
pub async fn app_quick_toggle(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<AppStateResponse, CommandError> {
    let result = quick_toggle(&app, &application, cfg!(target_os = "android")).await;
    let _ = app.tunnel_android().refresh_quick_tile();
    result
}

pub(crate) async fn quick_toggle(
    app: &AppHandle,
    application: &NativeApplication,
    skip_probe_refresh: bool,
) -> Result<AppStateResponse, CommandError> {
    let state = application.state().await;
    match state.phase {
        Phase::Connected => {
            application.stop().await.map_err(CommandError::from)?;
        }
        Phase::Ready | Phase::Error | Phase::ServerUnavailable => {
            let bootstrap = application
                .bootstrap(now_unix())
                .await
                .map_err(CommandError::from)?;
            if !bootstrap.access.can_connect {
                return Err(CommandError::new(
                    "access_expired",
                    "Срок доступа уже истёк",
                ));
            }
            if bootstrap.binding.is_none() {
                return Err(CommandError::new(
                    "peer_binding_required",
                    "Сначала выберите пир в приложении",
                ));
            }
            crate::platform::prepare_tunnel(app.clone())
                .await
                .map_err(CommandError::from_tunnel)?;
            refresh_installed_applications_before_start(
                app,
                application,
                bootstrap.defaults.layer,
                bootstrap.defaults.route_mode,
            )
            .await?;
            let options = ConnectOptions {
                layer: bootstrap.defaults.layer,
                tic_connection_mode: bootstrap.defaults.tic_connection_mode,
                route_mode: bootstrap.defaults.route_mode,
                probes: Vec::new(),
                allow_alternate: true,
            };
            if skip_probe_refresh {
                application
                    .start_without_probe_refresh(options, now_unix())
                    .await
                    .map_err(CommandError::from)?;
            } else {
                application
                    .start(options, now_unix())
                    .await
                    .map_err(CommandError::from)?;
            }
        }
        Phase::Connecting | Phase::Stopping | Phase::Measuring | Phase::Authenticating => {
            return Err(CommandError::new(
                "connection_busy",
                "Дождитесь завершения текущего действия",
            ));
        }
        Phase::SignedOut => {
            return Err(CommandError::new(
                "signed_out",
                "Нужно снова войти в приложение",
            ));
        }
        Phase::NeedsPeerBinding => {
            return Err(CommandError::new(
                "peer_binding_required",
                "Сначала выберите пир в приложении",
            ));
        }
        Phase::AccessExpired => {
            return Err(CommandError::new(
                "access_expired",
                "Срок доступа уже истёк",
            ));
        }
        Phase::UpdateRequired => {
            return Err(CommandError::new(
                "update_required",
                "Для продолжения необходимо обновить приложение",
            ));
        }
    }
    let state = application.state().await;
    let warning = application.split_tunnel_warning().await;
    Ok(AppStateResponse::new(state, warning))
}

#[tauri::command]
pub async fn app_login(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    updater: State<'_, Arc<NativeUpdater>>,
    request: LoginCommandRequest,
) -> Result<Bootstrap, CommandError> {
    let response = application
        .login(
            LoginParameters {
                login: request.login,
                password: request.password,
                device_name: request.device_name,
                platform: current_platform(),
                platform_version: request.platform_version,
                architecture: std::env::consts::ARCH.to_string(),
                app_version: env!("CARGO_PKG_VERSION").to_string(),
            },
            now_unix(),
        )
        .await
        .map_err(CommandError::from)?;
    let _ = refresh_installed_applications(&app, &application);
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
    );
    schedule_split_tunnel_sync(
        application.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    schedule_push_registration(
        app,
        application.inner().clone(),
        push_registration_scheduler.inner().clone(),
    );
    Ok(response)
}

#[tauri::command]
pub async fn app_bootstrap(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<Bootstrap, CommandError> {
    let _ = refresh_installed_applications(&app, &application);
    let response = application
        .bootstrap(now_unix())
        .await
        .map_err(CommandError::from)?;
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
    );
    schedule_split_tunnel_sync(
        application.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    schedule_push_registration(
        app,
        application.inner().clone(),
        push_registration_scheduler.inner().clone(),
    );
    Ok(response)
}

#[tauri::command]
pub async fn app_peer_options(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<PeerOptions, CommandError> {
    application.peer_options().await.map_err(Into::into)
}

#[tauri::command]
pub async fn app_bind_peer(
    application: State<'_, Arc<NativeApplication>>,
    request: BindPeerRequest,
) -> Result<SafePeerBindingResponse, CommandError> {
    application
        .bind_peer(request)
        .await
        .map(Into::into)
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_unbind_peer(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<SafePeerBindingResponse, CommandError> {
    application
        .unbind_peer()
        .await
        .map(Into::into)
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_refresh_probes(
    application: State<'_, Arc<NativeApplication>>,
    layer: Layer,
) -> Result<ProbeResults, CommandError> {
    application
        .refresh_probes(layer, now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_prepare_tunnel(
    app: AppHandle,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<(), CommandError> {
    match crate::platform::prepare_tunnel(app).await {
        Ok(()) => {
            diagnostics.record_named("tunnel.prepare_succeeded", None, None, None);
            Ok(())
        }
        Err(error) => {
            let command_error = CommandError::from_tunnel(error);
            diagnostics.record_named(
                "tunnel.prepare_failed",
                None,
                None,
                Some(&command_error.code),
            );
            Err(command_error)
        }
    }
}

#[tauri::command]
pub async fn app_start(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    request: StartCommandRequest,
) -> Result<Connection, CommandError> {
    refresh_installed_applications_before_start(
        &app,
        &application,
        request.layer,
        request.route_mode,
    )
    .await?;
    application
        .start(
            ConnectOptions {
                layer: request.layer,
                tic_connection_mode: request.tic_connection_mode,
                route_mode: request.route_mode,
                probes: Vec::new(),
                allow_alternate: request.allow_alternate,
            },
            now_unix(),
        )
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_start_saved_stray(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<String, CommandError> {
    refresh_installed_applications_before_start(
        &app,
        &application,
        Layer::Stray,
        RouteMode::Standalone,
    )
    .await?;
    application
        .start_saved_stray_offline(now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_stop(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Connection, CommandError> {
    application.stop().await.map_err(Into::into)
}

#[tauri::command]
pub async fn app_pin_stray(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Connection, CommandError> {
    application.pin_stray().await.map_err(Into::into)
}

#[tauri::command]
pub async fn app_unpin_stray(
    application: State<'_, Arc<NativeApplication>>,
    request: LeaseCommandRequest,
) -> Result<Connection, CommandError> {
    application
        .unpin_stray(&request.lease_id, now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_send_diagnostics(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<DiagnosticUploadResponse, CommandError> {
    let resource_snapshot = crate::resource_usage::ResourceSnapshot::capture(&app);
    let report = diagnostics.build_report(resource_snapshot).map_err(|_| {
        CommandError::new(
            "diagnostics_unavailable",
            "Не удалось подготовить диагностический отчёт",
        )
    })?;
    match application.upload_diagnostics(&report).await {
        Ok(response) => {
            diagnostics.record_named(
                "diagnostics.uploaded",
                None,
                Some(&response.request_id),
                None,
            );
            Ok(response)
        }
        Err(error) => {
            diagnostics.record_named(
                "diagnostics.upload_failed",
                None,
                None,
                Some("upload_failed"),
            );
            Err(error.into())
        }
    }
}

#[tauri::command]
pub fn app_update_status(
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    updater.status().map_err(update_command_error)
}

#[tauri::command]
pub fn app_update_set_automatic(
    application: State<'_, Arc<NativeApplication>>,
    updater: State<'_, Arc<NativeUpdater>>,
    enabled: bool,
) -> Result<UpdateStatusResponse, CommandError> {
    let response = updater
        .set_automatic(enabled)
        .map_err(update_command_error)?;
    if enabled {
        schedule_automatic_update(application.inner().clone(), updater.inner().clone());
    }
    Ok(response)
}

#[tauri::command]
pub async fn app_update_install(
    application: State<'_, Arc<NativeApplication>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    let bootstrap = application
        .bootstrap(now_unix())
        .await
        .map_err(CommandError::from)?;
    updater
        .observe(&bootstrap.update)
        .map_err(update_command_error)?;
    let access_token = application
        .current_access_token()
        .map_err(CommandError::from)?;
    updater
        .install_now(&access_token)
        .await
        .map_err(update_command_error)
}

#[tauri::command]
pub fn app_update_restart(
    app: AppHandle,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<(), CommandError> {
    if !updater.ready_to_restart() {
        return Err(CommandError::new(
            "update_not_ready",
            "Обновление ещё не готово к перезапуску",
        ));
    }
    app.restart();
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelCapabilitiesResponse {
    platform: &'static str,
    android_api_level: Option<u32>,
    address_split_tunnel: bool,
    application_split_tunnel: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelStateResponse {
    available: bool,
    enabled: bool,
    mode: SplitTunnelMode,
    exclude_local_networks: bool,
    mandatory_excluded_packages: Vec<String>,
    suggested_name_fragments: Vec<String>,
    selected_packages: Vec<String>,
    address_rules: Vec<SplitTunnelAddressRuleResponse>,
    warning: Option<String>,
    capabilities: SplitTunnelCapabilitiesResponse,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelAddressRuleResponse {
    id: i64,
    scope: &'static str,
    kind: &'static str,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelAddressRuleRequest {
    value: String,
    scope: SplitTunnelAddressRuleScope,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApplicationResponse {
    package_id: String,
    display_name: String,
    system: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSelectedPackageRequest {
    package_id: String,
    display_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSaveRequest {
    mode: SplitTunnelMode,
    exclude_local_networks: bool,
    selected_packages: Vec<SplitTunnelSelectedPackageRequest>,
}

impl From<SplitTunnelSaveRequest> for SplitTunnelSettingsUpdate {
    fn from(request: SplitTunnelSaveRequest) -> Self {
        Self {
            mode: request.mode,
            exclude_local_networks: request.exclude_local_networks,
            selected_packages: request
                .selected_packages
                .into_iter()
                .map(|package| SplitTunnelSelectedPackage {
                    package_id: package.package_id,
                    display_name: package.display_name,
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSaveResponse {
    saved: bool,
    requires_reconnect_confirmation: bool,
    state: SplitTunnelStateResponse,
}

#[tauri::command]
pub async fn app_split_tunnel_state(
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
) -> Result<SplitTunnelStateResponse, CommandError> {
    let _ = split_tunnel_scheduler
        .synchronize(&application, false)
        .await;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub fn app_split_tunnel_installed_applications(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Vec<InstalledApplicationResponse>, CommandError> {
    refresh_installed_applications(&app, &application)
}

#[tauri::command]
pub async fn app_split_tunnel_save(
    application: State<'_, Arc<NativeApplication>>,
    request: SplitTunnelSaveRequest,
    confirm_reconnect: bool,
) -> Result<SplitTunnelSaveResponse, CommandError> {
    let request = SplitTunnelSettingsUpdate::from(request);
    let reconnect = application
        .split_tunnel_settings_require_reconnect(&request)
        .await
        .map_err(CommandError::from)?;
    if reconnect && !confirm_reconnect {
        return Ok(SplitTunnelSaveResponse {
            saved: false,
            requires_reconnect_confirmation: true,
            state: split_tunnel_state(&application).await?,
        });
    }
    application
        .save_split_tunnel_settings(&request, now_unix())
        .await
        .map_err(CommandError::from)?;
    Ok(SplitTunnelSaveResponse {
        saved: true,
        requires_reconnect_confirmation: false,
        state: split_tunnel_state(&application).await?,
    })
}

#[tauri::command]
pub async fn app_split_tunnel_refresh(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
) -> Result<SplitTunnelStateResponse, CommandError> {
    refresh_installed_applications(&app, &application)?;
    split_tunnel_scheduler
        .synchronize(&application, true)
        .await?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_split_tunnel_add_address_rule(
    application: State<'_, Arc<NativeApplication>>,
    request: SplitTunnelAddressRuleRequest,
) -> Result<SplitTunnelStateResponse, CommandError> {
    application
        .add_split_tunnel_address_rule(
            &SplitTunnelAddressRuleUpdate {
                value: request.value,
                scope: request.scope,
            },
            now_unix(),
        )
        .await
        .map_err(CommandError::from)?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_split_tunnel_remove_address_rule(
    application: State<'_, Arc<NativeApplication>>,
    rule_id: i64,
    scope: SplitTunnelAddressRuleScope,
) -> Result<SplitTunnelStateResponse, CommandError> {
    application
        .remove_split_tunnel_address_rule(rule_id, scope, now_unix())
        .await
        .map_err(CommandError::from)?;
    split_tunnel_state(&application).await
}

#[tauri::command]
pub async fn app_notifications(
    application: State<'_, Arc<NativeApplication>>,
    cursor: Option<i64>,
) -> Result<AppNotificationList, CommandError> {
    application
        .notifications(cursor, 30)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_notification_read(
    application: State<'_, Arc<NativeApplication>>,
    message_id: i64,
) -> Result<AppNotificationReadResponse, CommandError> {
    application
        .mark_notification_read(message_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_notifications_read_all(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<AppNotificationReadResponse, CommandError> {
    application
        .mark_all_notifications_read()
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_register_push_token(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    token: String,
) -> Result<(), CommandError> {
    let result = application
        .register_push_token(&token)
        .await
        .map_err(Into::into);
    #[cfg(target_os = "android")]
    if result.is_ok() {
        use tauri_plugin_push_android::PushAndroidExt;

        let _ = app.push_android().confirm(&token);
    }
    #[cfg(not(target_os = "android"))]
    let _ = app;
    result
}

#[tauri::command]
pub async fn app_logout(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
) -> Result<(), CommandError> {
    push_registration_scheduler
        .logout(&app, &application)
        .await
        .map_err(Into::into)
}

fn observe_and_schedule_update(
    application: Arc<NativeApplication>,
    updater: Arc<NativeUpdater>,
    bootstrap: &Bootstrap,
) {
    if updater.observe(&bootstrap.update).is_ok() {
        schedule_automatic_update(application, updater);
    }
}

fn schedule_automatic_update(application: Arc<NativeApplication>, updater: Arc<NativeUpdater>) {
    tauri::async_runtime::spawn(async move {
        let Ok(access_token) = application.current_access_token() else {
            return;
        };
        let _ = updater.install_automatically(&access_token).await;
    });
}

fn schedule_split_tunnel_sync(
    application: Arc<NativeApplication>,
    scheduler: Arc<SplitTunnelScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        let _ = scheduler.synchronize(&application, false).await;
    });
}

fn schedule_push_registration(
    app: AppHandle,
    application: Arc<NativeApplication>,
    scheduler: Arc<PushRegistrationScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        scheduler.synchronize(&app, &application).await;
    });
}

async fn split_tunnel_state(
    application: &NativeApplication,
) -> Result<SplitTunnelStateResponse, CommandError> {
    let capabilities = application
        .split_tunnel_capabilities()
        .await
        .map_err(CommandError::from)?;
    let warning = application.split_tunnel_warning().await;
    let policy = application
        .cached_split_tunnel_policy()
        .map_err(CommandError::from)?;
    Ok(match policy {
        Some(policy) => SplitTunnelStateResponse {
            available: true,
            enabled: policy.enabled,
            mode: policy.mode,
            exclude_local_networks: policy.exclude_local_networks,
            mandatory_excluded_packages: policy.mandatory_excluded_packages,
            suggested_name_fragments: policy.suggested_name_fragments,
            selected_packages: policy.selected_packages,
            address_rules: policy
                .address_rules
                .into_iter()
                .map(|rule| SplitTunnelAddressRuleResponse {
                    id: rule.id,
                    scope: match rule.scope {
                        SplitTunnelAddressRuleScope::ThisDevice => "this_device",
                        SplitTunnelAddressRuleScope::AllDevices => "all_devices",
                    },
                    kind: match rule.kind {
                        nelomai_contracts::SplitTunnelAddressRuleKind::Ipv4 => "ipv4",
                        nelomai_contracts::SplitTunnelAddressRuleKind::Domain => "domain",
                    },
                    value: rule.value,
                })
                .collect(),
            warning,
            capabilities: capabilities.into(),
        },
        None => SplitTunnelStateResponse {
            available: false,
            enabled: false,
            mode: SplitTunnelMode::ExcludeSelected,
            exclude_local_networks: true,
            mandatory_excluded_packages: Vec::new(),
            suggested_name_fragments: Vec::new(),
            selected_packages: Vec::new(),
            address_rules: Vec::new(),
            warning,
            capabilities: capabilities.into(),
        },
    })
}

impl From<TunnelCapabilities> for SplitTunnelCapabilitiesResponse {
    fn from(capabilities: TunnelCapabilities) -> Self {
        Self {
            platform: match capabilities.platform {
                TunnelPlatform::Android => "android",
                TunnelPlatform::Windows => "windows",
                TunnelPlatform::Linux => "linux",
                TunnelPlatform::Macos => "macos",
                TunnelPlatform::Unknown => "unknown",
            },
            android_api_level: capabilities.android_api_level,
            address_split_tunnel: capabilities.address_split_tunnel,
            application_split_tunnel: capabilities.application_split_tunnel,
        }
    }
}

fn refresh_installed_applications(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<Vec<InstalledApplicationResponse>, CommandError> {
    let response = app.tunnel_android().installed_applications().map_err(|_| {
        CommandError::new(
            "installed_applications_unavailable",
            "Не удалось получить список приложений",
        )
    })?;
    application.set_split_tunnel_installed_packages(
        response
            .applications
            .iter()
            .map(|application| SplitTunnelSelectedPackage {
                package_id: application.package_id.clone(),
                display_name: application.display_name.clone(),
            })
            .collect(),
    );
    Ok(response
        .applications
        .into_iter()
        .map(|application| InstalledApplicationResponse {
            package_id: application.package_id,
            display_name: application.display_name,
            system: application.system,
        })
        .collect())
}

async fn refresh_installed_applications_before_start(
    app: &AppHandle,
    application: &NativeApplication,
    layer: Layer,
    route_mode: RouteMode,
) -> Result<(), CommandError> {
    let capabilities = application
        .split_tunnel_capabilities()
        .await
        .map_err(CommandError::from)?;
    let policy = application
        .cached_split_tunnel_policy()
        .map_err(CommandError::from)?;
    let inventory_required = capabilities.application_split_tunnel
        && policy.as_ref().is_some_and(|policy| {
            split_tunnel_active(SplitTunnelContext {
                global_enabled: policy.enabled,
                platform: capabilities.platform,
                android_api_level: capabilities.android_api_level,
                layer,
                route_mode,
            })
        });
    if inventory_required {
        if refresh_installed_applications(app, application)?.is_empty() {
            return Err(CommandError::new(
                "installed_applications_unavailable",
                "Не удалось получить список приложений",
            ));
        }
    } else {
        let _ = refresh_installed_applications(app, application);
    }
    Ok(())
}

fn update_command_error(error: String) -> CommandError {
    CommandError::new("update_failed", update_error_message(&error))
}

fn update_error_message(error: &str) -> &'static str {
    if error.contains("backend is unavailable") {
        "На этом устройстве обновление устанавливается вручную"
    } else if error.contains("install_permission_denied") {
        "Разрешите Nelomai устанавливать обновления и повторите попытку"
    } else if error.contains("preference") {
        "Не удалось сохранить настройки обновлений"
    } else {
        "Не удалось установить обновление"
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or_default()
}

#[cfg(target_os = "android")]
fn current_platform() -> Platform {
    Platform::Android
}

#[cfg(windows)]
fn current_platform() -> Platform {
    Platform::Windows
}

#[cfg(target_os = "macos")]
fn current_platform() -> Platform {
    Platform::Macos
}

#[cfg(target_os = "linux")]
fn current_platform() -> Platform {
    Platform::Linux
}

#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_contracts::{ApiVersion, PeerBinding};

    #[test]
    fn binding_response_never_serializes_wireguard_configuration() {
        let response = SafePeerBindingResponse::from(PeerBindingResponse {
            api_version: ApiVersion::V1,
            request_id: "request-1".to_string(),
            binding: None::<PeerBinding>,
            configuration: Some("PrivateKey = secret".to_string()),
        });

        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains("PrivateKey"));
        assert!(!json.contains("configuration"));
    }

    #[test]
    fn split_tunnel_command_models_use_camel_case_without_application_icons() {
        let request: SplitTunnelSaveRequest = serde_json::from_value(serde_json::json!({
            "mode": "exclude_selected",
            "excludeLocalNetworks": true,
            "selectedPackages": [{
                "packageId": "com.example.browser",
                "displayName": "Browser"
            }]
        }))
        .unwrap();
        let update = SplitTunnelSettingsUpdate::from(request);
        assert_eq!(update.mode, SplitTunnelMode::ExcludeSelected);
        assert!(update.exclude_local_networks);
        assert_eq!(
            update.selected_packages[0].package_id,
            "com.example.browser"
        );

        let response = InstalledApplicationResponse {
            package_id: "com.example.browser".to_string(),
            display_name: "Browser".to_string(),
            system: false,
        };
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["packageId"], "com.example.browser");
        assert!(value.get("icon").is_none());
    }

    #[test]
    fn route_errors_do_not_look_like_a_missing_tunnel_service() {
        let error = CommandError::from_core(CoreError::Tunnel("route_conflict".to_string()));

        assert_eq!(error.code, "route_conflict");
        assert!(error.message.contains("маршрут"));
        assert!(!error.message.contains("Переустановите"));
    }

    #[test]
    fn split_tunnel_stop_failure_keeps_its_actionable_error() {
        let error = CommandError::from_core(CoreError::SplitTunnel(
            "split_tunnel_stop_failed".to_string(),
        ));

        assert_eq!(error.code, "split_tunnel_stop_failed");
        assert!(error.message.contains("остановить подключение"));
    }
}
