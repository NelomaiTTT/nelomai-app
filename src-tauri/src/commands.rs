use crate::connection_metrics::{ConnectionMetricsResponse, ConnectionMetricsTracker};
use crate::diagnostics::AppDiagnostics;
use crate::updates::{NativeUpdater, UpdateStatusResponse};
use crate::{
    preferences::{connection_egress_mode, AppPreferenceStore, DnsProvider},
    NativeApplication, PushRegistrationScheduler, SplitTunnelScheduler,
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
    ConnectionIntentCapability, EgressMode, Layer, PeerBinding, PeerBindingResponse, PeerOptions,
    Platform, ProbeResults, RouteMode, SplitTunnelAddressRuleScope, SplitTunnelAddressRuleUpdate,
    SplitTunnelMode, SplitTunnelSelectedPackage, SplitTunnelSettingsUpdate, TicConnectionMode,
};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_tunnel_android::TunnelAndroidExt;

#[cfg(target_os = "android")]
static ANDROID_BACKGROUND_PROVISION_GATE: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());

#[cfg(target_os = "android")]
static ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX: AtomicI64 = AtomicI64::new(0);

#[cfg(any(target_os = "android", test))]
const ANDROID_BACKGROUND_REFRESH_WINDOW_SECONDS: i64 = 7 * 24 * 60 * 60;

#[cfg(target_os = "android")]
const ANDROID_QUICK_RECONCILE_RETRY_SECONDS: i64 = 15;

const STARTUP_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(45);

#[cfg(any(target_os = "android", test))]
fn should_attempt_android_background_recovery(
    error: &ApplicationError,
    background_configured: bool,
) -> bool {
    background_configured && matches!(error, ApplicationError::Core(CoreError::SignedOut))
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AndroidBackgroundRecoveryFailure {
    AccessExpired,
    ClearAndFallbackRefresh,
    FallbackRefresh,
    Retryable,
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AndroidBackgroundProvisionMode {
    Noop,
    UiAuthenticatedTwoPhase,
    RefreshStoredCapability,
    Legacy,
}

#[cfg(any(target_os = "android", test))]
fn android_background_provision_mode(
    status: &tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse,
    device_id: &str,
    desired_capability_enabled: bool,
    now: i64,
) -> AndroidBackgroundProvisionMode {
    let same_device = status.device_id.as_deref() == Some(device_id);
    let token_is_fresh = status.expires_at_unix.is_some_and(|expires_at| {
        expires_at > now.saturating_add(ANDROID_BACKGROUND_REFRESH_WINDOW_SECONDS)
    });
    if status.mutation_pending {
        AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase
    } else if status.configured
        && status.mutation_ready
        && same_device
        && status.capability_enabled == desired_capability_enabled
        && (!status.capability_enabled
            || status
                .capability_expires_at_unix
                .is_some_and(|expires_at| expires_at > now))
        && token_is_fresh
    {
        AndroidBackgroundProvisionMode::Noop
    } else if status.configured && status.mutation_ready && same_device && token_is_fresh {
        AndroidBackgroundProvisionMode::RefreshStoredCapability
    } else if desired_capability_enabled {
        AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase
    } else {
        AndroidBackgroundProvisionMode::Legacy
    }
}

#[cfg(any(target_os = "android", test))]
fn android_background_rotation_fallback(
    desired_capability_enabled: bool,
) -> Option<AndroidBackgroundProvisionMode> {
    desired_capability_enabled.then_some(AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase)
}

#[cfg(any(target_os = "android", test))]
fn android_background_legacy_fallback_after_ui_failure(
    desired_capability_enabled: bool,
    latest_status: &tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse,
) -> bool {
    !desired_capability_enabled && !latest_status.mutation_pending
}

#[cfg(any(target_os = "android", test))]
fn classify_android_background_recovery_error(code: &str) -> AndroidBackgroundRecoveryFailure {
    match code {
        "invalid_background_token" | "invalid_background_recovery" => {
            AndroidBackgroundRecoveryFailure::ClearAndFallbackRefresh
        }
        "activation_not_applied" | "background_recovery_unsupported" => {
            AndroidBackgroundRecoveryFailure::FallbackRefresh
        }
        "app_access_unavailable" => AndroidBackgroundRecoveryFailure::AccessExpired,
        _ => AndroidBackgroundRecoveryFailure::Retryable,
    }
}

#[cfg(any(target_os = "android", test))]
async fn await_detached_on_cancellation<F, T>(future: F) -> Result<T, tokio::task::JoinError>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future).await
}

async fn bootstrap_application_for_startup(
    app: &AppHandle,
    application: &NativeApplication,
    diagnostics: &AppDiagnostics,
    now_unix: i64,
) -> Result<Bootstrap, CommandError> {
    #[cfg(target_os = "android")]
    {
        let first_error = match application.bootstrap_without_refresh(now_unix).await {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        if !matches!(first_error, ApplicationError::Core(CoreError::SignedOut)) {
            return Err(first_error.into());
        }
        let background_configured = app
            .tunnel_android()
            .background_credential_status()
            .map_err(|_| {
                CommandError::new(
                    "background_storage_unavailable",
                    "Не удалось проверить сохранённую сессию. Повторите запуск приложения",
                )
            })?
            .configured;
        if !should_attempt_android_background_recovery(&first_error, background_configured) {
            return application.bootstrap(now_unix).await.map_err(Into::into);
        }

        diagnostics.record_named("startup.auth_recovery.begin", None, None, None);
        let install_secret = application.install_secret().map_err(CommandError::from)?;
        let recovery_app = app.clone();
        let recovered = await_detached_on_cancellation(async move {
            recovery_app
                .tunnel_android()
                .recover_background_session(
                    tauri_plugin_tunnel_android::BackgroundSessionRecoveryRequest {
                        install_secret,
                    },
                )
                .await
        })
        .await
        .map_err(|_| {
            CommandError::new(
                "session_recovery_failed",
                "Не удалось завершить восстановление сессии. Повторите запуск приложения",
            )
        })?
        .map_err(|_| {
            CommandError::new(
                "session_recovery_failed",
                "Не удалось восстановить сессию. Проверьте сеть и повторите запуск приложения",
            )
        })?;
        if let Some(code) = recovered.error_code.as_deref() {
            return match classify_android_background_recovery_error(code) {
                AndroidBackgroundRecoveryFailure::ClearAndFallbackRefresh => {
                    app.tunnel_android().clear_background().map_err(|_| {
                        CommandError::new(
                            "background_storage_unavailable",
                            "Не удалось очистить недействительную сессию. Повторите запуск приложения",
                        )
                    })?;
                    application.bootstrap(now_unix).await.map_err(Into::into)
                }
                AndroidBackgroundRecoveryFailure::FallbackRefresh => {
                    application.bootstrap(now_unix).await.map_err(Into::into)
                }
                AndroidBackgroundRecoveryFailure::AccessExpired => {
                    Err(CommandError::from_core(CoreError::AccessExpired))
                }
                AndroidBackgroundRecoveryFailure::Retryable => Err(CommandError::new(
                    code,
                    "Не удалось восстановить сессию. Проверьте сеть и повторите запуск приложения",
                )),
            };
        }
        let access_token = recovered.access_token.as_deref().ok_or_else(|| {
            CommandError::new(
                "invalid_background_recovery_response",
                "Панель вернула неполный ответ. Повторите запуск приложения",
            )
        })?;
        let refresh_token = recovered.refresh_token.as_deref().ok_or_else(|| {
            CommandError::new(
                "invalid_background_recovery_response",
                "Панель вернула неполный ответ. Повторите запуск приложения",
            )
        })?;
        application
            .replace_session_tokens(access_token, refresh_token)
            .await
            .map_err(CommandError::from)?;
        diagnostics.record_named("startup.auth_recovery.completed", None, None, None);
        application
            .bootstrap_without_refresh(now_unix)
            .await
            .map_err(Into::into)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, diagnostics);
        application.bootstrap(now_unix).await.map_err(Into::into)
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    code: String,
    message: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsDefenderStatusResponse {
    supported: bool,
    state: String,
    dll_present: bool,
    dll_path: Option<String>,
    detail_code: Option<String>,
    antivirus_products: Vec<WindowsAntivirusProductResponse>,
    antivirus_detail_code: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsAntivirusProductResponse {
    name: String,
    state: String,
    signatures_up_to_date: Option<bool>,
    is_default: Option<bool>,
    is_microsoft_defender: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupStage {
    FrontendMounted,
    FrontendFirstFrame,
    BootstrapSlow,
}

impl StartupStage {
    fn event_name(&self) -> &'static str {
        match self {
            Self::FrontendMounted => "startup.frontend.mounted",
            Self::FrontendFirstFrame => "startup.frontend.first_frame",
            Self::BootstrapSlow => "startup.bootstrap.slow",
        }
    }
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
    pub(crate) fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn code(&self) -> &str {
        &self.code
    }

    fn from_api(error: CoreApiError) -> Self {
        match error {
            CoreApiError::Unauthorized => Self::new("signed_out", "Нужно снова войти в приложение"),
            CoreApiError::AccessExpired => Self::new("access_expired", "Срок доступа уже истёк"),
            CoreApiError::Retryable => {
                Self::new("temporarily_unavailable", "Не удалось связаться с панелью")
            }
            CoreApiError::Rejected { code, message, .. } => Self::new(code, message),
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
                "tunnel_handshake_timeout" => Self::new(
                    "tunnel_handshake_timeout",
                    "Stray-сервер не ответил через текущую сеть",
                ),
                code if tunnel_service_error(code) => Self::new(
                    "tunnel_service_unavailable",
                    "Служба подключения недоступна. Повторите действие и разрешите её восстановление",
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
            "tunnel_handshake_timeout" => Self::new(
                "tunnel_handshake_timeout",
                "Stray-сервер не ответил через текущую сеть",
            ),
            "vpn_permission_denied" => Self::new(
                "vpn_permission_denied",
                "Без разрешения Android подключение невозможно",
            ),
            "tunnel_backend_unavailable" => Self::new(
                "tunnel_backend_unavailable",
                "Система подключения недоступна на этом устройстве",
            ),
            "service_unavailable"
            | "service_timeout"
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
            "helper_installer_timeout" => Self::new(
                "helper_installer_timeout",
                "Системная настройка подключения не завершилась вовремя",
            ),
            "helper_resources_unavailable" => Self::new(
                "helper_resources_unavailable",
                "В установленном приложении отсутствуют компоненты подключения",
            ),
            "defender_exclusion_missing" => Self::new(
                "defender_exclusion_missing",
                "Microsoft Defender не исключает компонент AmneziaWG из проверки",
            ),
            "amneziawg_component_missing" => Self::new(
                "amneziawg_component_missing",
                "Антивирус мог удалить или заблокировать компонент AmneziaWG",
            ),
            "antivirus_may_block_amneziawg" => Self::new(
                "antivirus_may_block_amneziawg",
                "Активный сторонний антивирус может блокировать компонент AmneziaWG",
            ),
            "defender_exclusion_repair_cancelled" => Self::new(
                "defender_exclusion_repair_cancelled",
                "Исправление настройки Microsoft Defender отменено",
            ),
            "defender_exclusion_repair_failed" => Self::new(
                "defender_exclusion_repair_failed",
                "Не удалось добавить исключение Microsoft Defender",
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
            "endpoint_route_unavailable" => {
                "Не удалось безопасно проложить маршрут до Stray-сервера. Переподключите устройство к сети и нажмите «Старт» снова"
            }
            "endpoint_route_lost" => {
                "Сеть изменилась, поэтому Stray остановлен для защиты. Нажмите «Старт» снова"
            }
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

fn tunnel_service_error(code: &str) -> bool {
    matches!(
        code,
        "service_unavailable"
            | "service_timeout"
            | "tunnel_service_unavailable"
            | "tunnel_service_timeout"
            | "service_outdated"
            | "service_stopping"
            | "udp_rebind_failed"
            | "udp_rebind_timeout"
            | "unsupported_protocol"
            | "unauthorized_client"
            | "truncated_frame"
            | "missing_service_version"
    )
}

fn repairable_stop_error(error: &ApplicationError) -> bool {
    matches!(
        error,
        ApplicationError::Core(CoreError::Tunnel(code)) if tunnel_service_error(code)
    )
}

async fn stop_connection(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<Option<Connection>, CommandError> {
    let intent_cancelled = cancel_desktop_connection_intent(app).await;
    let result = match application.stop().await {
        Ok(connection) => Ok(Some(connection)),
        Err(ApplicationError::Core(CoreError::SavedConnectionUnavailable)) if intent_cancelled => {
            Ok(None)
        }
        Err(error) if repairable_stop_error(&error) => {
            crate::platform::prepare_tunnel_for_stop(app.clone())
                .await
                .map_err(CommandError::from_tunnel)?;
            application.stop().await.map(Some).map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    };
    #[cfg(desktop)]
    if result.is_ok() {
        queue_desktop_tunnel_stopped(app).await;
    }
    result
}

pub(crate) async fn stop_for_shutdown(
    app: &AppHandle,
    application: &NativeApplication,
) -> Result<(), CommandError> {
    let intent_cancelled = cancel_desktop_connection_intent(app).await;
    let state = application.state().await;
    if !shutdown_requires_stop(&state, intent_cancelled) {
        return Ok(());
    }

    let result = match application.stop_for_shutdown().await {
        Ok(_) => Ok(()),
        Err(ApplicationError::Core(CoreError::SavedConnectionUnavailable)) if intent_cancelled => {
            Ok(())
        }
        Err(error) if repairable_stop_error(&error) => {
            crate::platform::prepare_tunnel_for_stop(app.clone())
                .await
                .map_err(CommandError::from_tunnel)?;
            application
                .stop_for_shutdown()
                .await
                .map(|_| ())
                .map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    };
    #[cfg(desktop)]
    if result.is_ok() {
        queue_desktop_tunnel_stopped(app).await;
    }
    result
}

fn shutdown_requires_stop(state: &CoreState, intent_cancelled: bool) -> bool {
    intent_cancelled
        || state.connection.is_some()
        || matches!(
            state.phase,
            Phase::Connected | Phase::Connecting | Phase::Stopping
        )
}

#[cfg(not(target_os = "android"))]
async fn cancel_desktop_connection_intent(app: &AppHandle) -> bool {
    use tauri::Manager;

    let runtime = app
        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
        .inner()
        .clone();
    runtime.cancel().await
}

#[cfg(target_os = "android")]
async fn cancel_desktop_connection_intent(_app: &AppHandle) -> bool {
    false
}

#[cfg(desktop)]
fn begin_desktop_tunnel_diagnostics(app: &AppHandle, session_id: &str) {
    use tauri::Manager;

    let diagnostics = app.state::<Arc<AppDiagnostics>>();
    let now = now_unix();
    if let Ok(observation) = diagnostics.observe_automatic_tunnel(Some(session_id), true, now) {
        if observation.interval_started.is_some() {
            diagnostics.begin_automatic_resource_interval(
                &observation,
                crate::resource_usage::ResourceSnapshot::capture(app),
            );
        }
    }
}

#[cfg(desktop)]
async fn queue_desktop_tunnel_stopped(app: &AppHandle) {
    use tauri::Manager;

    let diagnostics = app.state::<Arc<AppDiagnostics>>().inner().clone();
    let tunnel = app
        .state::<Arc<crate::platform::PlatformTunnelController>>()
        .inner()
        .clone();
    let now = now_unix();
    let queued = diagnostics
        .observe_automatic_tunnel(None, false, now)
        .is_ok_and(|observation| observation.seal_pending);
    if !queued {
        return;
    }
    let Ok(Some(seal)) = diagnostics.pending_automatic_seal() else {
        return;
    };
    let helper_log = crate::platform::diagnostic_helper_log(&tunnel).await;
    let resource_snapshot = crate::resource_usage::ResourceSnapshot::capture(app);
    match diagnostics.materialize_automatic_report(&seal, resource_snapshot, helper_log) {
        Ok(()) => diagnostics.record_named(
            "diagnostics.automatic_report_queued",
            Some(&seal.session_id),
            Some(&seal.report_id),
            Some(&seal.trigger),
        ),
        Err(error) => diagnostics.record_named(
            "diagnostics.automatic_report_queue_failed",
            Some(&seal.session_id),
            None,
            Some(&error.kind().to_string()),
        ),
    }
}

#[cfg(desktop)]
async fn prepare_desktop_logout(
    app: &AppHandle,
    application: &NativeApplication,
    diagnostics: &AppDiagnostics,
) {
    use nelomai_client_tunnel::{TunnelController, TunnelError, TunnelStatus};

    let session_id = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let tunnel = app
        .state::<Arc<crate::platform::PlatformTunnelController>>()
        .inner()
        .clone();
    let status = tunnel.status().await;
    let stop_result = if matches!(status, Ok(TunnelStatus::Stopped | TunnelStatus::Failed)) {
        Ok(())
    } else {
        match tunnel.stop().await {
            Err(TunnelError::Backend(code)) if tunnel_service_error(&code) => {
                match crate::platform::prepare_tunnel_for_stop(app.clone()).await {
                    Ok(()) => tunnel.stop().await,
                    Err(error) => Err(error),
                }
            }
            result => result,
        }
    };
    match stop_result {
        Ok(()) => {
            if let Err(error) = application.reset_transport() {
                diagnostics.record_named(
                    "connection.transport_reset_failed",
                    session_id.as_deref(),
                    None,
                    Some(&error.to_string()),
                );
            }
            queue_desktop_tunnel_stopped(app).await;
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                crate::upload_latest_automatic_diagnostics_for_logout(application, diagnostics),
            )
            .await;
        }
        Err(error) => diagnostics.record_named(
            "diagnostics.logout_tunnel_stop_failed",
            session_id.as_deref(),
            None,
            Some(&error.to_string()),
        ),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateResponse {
    phase: &'static str,
    connection: Option<Connection>,
    connection_intent_status: &'static str,
    next_retry_at_unix: Option<i64>,
    warning: Option<String>,
    metrics: Option<ConnectionMetricsResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartCommandResponse {
    status: &'static str,
    connection: Option<Connection>,
    next_retry_at_unix: Option<i64>,
}

impl StartCommandResponse {
    pub(crate) fn connected(connection: Connection) -> Self {
        Self {
            status: "connected",
            connection: Some(connection),
            next_retry_at_unix: None,
        }
    }

    #[cfg(not(target_os = "android"))]
    pub(crate) fn recovering(next_retry_at_unix: Option<i64>) -> Self {
        Self {
            status: "recovering",
            connection: None,
            next_retry_at_unix,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPreferencesResponse {
    close_to_tray_supported: bool,
    close_to_tray: bool,
    dns_provider: DnsProvider,
    personal_tic_egress_mode: EgressMode,
    dynamic_tic_egress_mode: EgressMode,
}

impl AppStateResponse {
    fn new(
        state: CoreState,
        warning: Option<String>,
        metrics: Option<ConnectionMetricsResponse>,
        connection_intent_status: nelomai_client_core::ConnectionIntentStatus,
        next_retry_at_unix: Option<i64>,
    ) -> Self {
        let phase = if connection_intent_status
            == nelomai_client_core::ConnectionIntentStatus::Recovering
            && matches!(
                state.phase,
                Phase::Ready | Phase::Connecting | Phase::Stopping | Phase::ServerUnavailable
            ) {
            "connecting"
        } else {
            phase_name(state.phase)
        };
        Self {
            phase,
            connection: state.connection,
            connection_intent_status: connection_intent_status_name(connection_intent_status),
            next_retry_at_unix,
            warning,
            metrics,
        }
    }
}

fn connection_intent_status_name(
    status: nelomai_client_core::ConnectionIntentStatus,
) -> &'static str {
    match status {
        nelomai_client_core::ConnectionIntentStatus::None => "none",
        nelomai_client_core::ConnectionIntentStatus::Recovering => "recovering",
        nelomai_client_core::ConnectionIntentStatus::BlockedTerminal => "blocked_terminal",
    }
}

async fn current_connection_metrics(
    tracker: &ConnectionMetricsTracker,
    context: Option<&nelomai_client_core::ConnectionMetricsContext>,
) -> Option<ConnectionMetricsResponse> {
    tracker.snapshot(&context?.session_id).await
}

#[cfg(not(target_os = "android"))]
async fn current_connection_intent(
    app: &AppHandle,
) -> (nelomai_client_core::ConnectionIntentStatus, Option<i64>) {
    use tauri::Manager;

    let snapshot = app
        .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
        .snapshot()
        .await;
    (snapshot.status, snapshot.next_retry_at_unix)
}

#[cfg(target_os = "android")]
async fn current_connection_intent(
    _app: &AppHandle,
) -> (nelomai_client_core::ConnectionIntentStatus, Option<i64>) {
    (nelomai_client_core::ConnectionIntentStatus::None, None)
}

#[cfg(desktop)]
fn metrics_view_is_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main").is_some_and(|window| {
        window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false)
    })
}

#[cfg(not(desktop))]
fn metrics_view_is_visible(_app: &AppHandle) -> bool {
    true
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
    device_id: String,
    layer: Layer,
    tic_connection_mode: TicConnectionMode,
    route_mode: RouteMode,
    egress_mode: EgressMode,
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
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    metrics: State<'_, Arc<ConnectionMetricsTracker>>,
) -> Result<AppStateResponse, CommandError> {
    if metrics_view_is_visible(&app) {
        metrics.mark_observed().await;
    }
    let quick_state_change = app
        .tunnel_android()
        .take_quick_state_change()
        .unwrap_or_default();
    let quick_state_changed = quick_state_change.changed;
    let state = if quick_state_changed && quick_reconcile_is_due(now_unix()) {
        match application.bootstrap(now_unix()).await {
            Ok(response) => {
                #[cfg(desktop)]
                diagnostics.set_automatic_device(&response.device.id);
                provision_android_background_resilient(
                    app.clone(),
                    application.inner().clone(),
                    diagnostics.inner().clone(),
                    response.device.id,
                    response.capabilities,
                )
                .await;
                if app
                    .tunnel_android()
                    .acknowledge_quick_state_change(quick_state_change.revision)
                    .is_ok()
                {
                    clear_quick_reconcile_retry();
                } else {
                    defer_quick_reconcile(now_unix());
                }
                application.state().await
            }
            Err(_) => {
                defer_quick_reconcile(now_unix());
                application.reconcile_external_tunnel_state().await
            }
        }
    } else if quick_state_changed {
        application.reconcile_external_tunnel_state().await
    } else {
        application.state().await
    };
    let warning = application.split_tunnel_warning().await;
    let metrics_context = application.connection_metrics_context().await;
    let current_metrics = current_connection_metrics(&metrics, metrics_context.as_ref()).await;
    let (intent_status, next_retry_at_unix) = current_connection_intent(&app).await;
    Ok(AppStateResponse::new(
        state,
        warning,
        current_metrics,
        intent_status,
        next_retry_at_unix,
    ))
}

#[cfg(target_os = "android")]
fn quick_reconcile_is_due(now_unix: i64) -> bool {
    now_unix >= ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.load(Ordering::Relaxed)
}

#[cfg(not(target_os = "android"))]
fn quick_reconcile_is_due(_now_unix: i64) -> bool {
    true
}

#[cfg(target_os = "android")]
fn defer_quick_reconcile(now_unix: i64) {
    ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.store(
        now_unix.saturating_add(ANDROID_QUICK_RECONCILE_RETRY_SECONDS),
        Ordering::Relaxed,
    );
}

#[cfg(not(target_os = "android"))]
fn defer_quick_reconcile(_now_unix: i64) {}

#[cfg(target_os = "android")]
fn clear_quick_reconcile_retry() {
    ANDROID_QUICK_RECONCILE_RETRY_AFTER_UNIX.store(0, Ordering::Relaxed);
}

#[cfg(not(target_os = "android"))]
fn clear_quick_reconcile_retry() {}

#[tauri::command]
pub fn app_preferences(preferences: State<'_, Arc<AppPreferenceStore>>) -> AppPreferencesResponse {
    let current = preferences.get();
    AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: current.close_to_tray,
        dns_provider: current.dns_provider,
        personal_tic_egress_mode: current.personal_tic_egress_mode,
        dynamic_tic_egress_mode: current.dynamic_tic_egress_mode,
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
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

#[tauri::command]
pub fn app_set_dns_provider(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    preferences: State<'_, Arc<AppPreferenceStore>>,
    provider: DnsProvider,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences.set_dns_provider(provider).map_err(|_| {
        CommandError::new(
            "preferences_unavailable",
            "Не удалось сохранить настройки приложения",
        )
    })?;
    let dns_servers = saved.dns_provider.servers();
    application.set_dns_servers(dns_servers.clone());
    let _ = app
        .tunnel_android()
        .update_quick_dns(tauri_plugin_tunnel_android::DnsServersRequest {
            dns_servers: dns_servers.iter().map(ToString::to_string).collect(),
        });
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

#[tauri::command]
pub fn app_set_tic_egress_mode(
    preferences: State<'_, Arc<AppPreferenceStore>>,
    connection_mode: TicConnectionMode,
    egress_mode: EgressMode,
) -> Result<AppPreferencesResponse, CommandError> {
    let saved = preferences
        .set_tic_egress_mode(connection_mode, egress_mode)
        .map_err(|_| {
            CommandError::new(
                "preferences_unavailable",
                "Не удалось сохранить настройки приложения",
            )
        })?;
    Ok(AppPreferencesResponse {
        close_to_tray_supported: cfg!(desktop),
        close_to_tray: saved.close_to_tray,
        dns_provider: saved.dns_provider,
        personal_tic_egress_mode: saved.personal_tic_egress_mode,
        dynamic_tic_egress_mode: saved.dynamic_tic_egress_mode,
    })
}

pub(crate) async fn quick_toggle(
    app: &AppHandle,
    application: &NativeApplication,
    skip_probe_refresh: bool,
) -> Result<AppStateResponse, CommandError> {
    let state = application.state().await;
    let (intent_status, _) = current_connection_intent(app).await;
    if intent_status != nelomai_client_core::ConnectionIntentStatus::None {
        stop_connection(app, application).await?;
    } else {
        match state.phase {
            Phase::Connected => {
                stop_connection(app, application).await?;
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
                let binding_egress_mode = bootstrap
                    .binding
                    .as_ref()
                    .map(|binding| binding.egress_mode)
                    .ok_or_else(|| {
                        CommandError::new(
                            "peer_binding_required",
                            "Сначала выберите пир в приложении",
                        )
                    })?;
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
                    egress_mode: connection_egress_mode(
                        bootstrap.defaults.layer,
                        bootstrap.defaults.route_mode,
                        bootstrap.defaults.tic_connection_mode,
                        app.state::<Arc<AppPreferenceStore>>().get(),
                        binding_egress_mode,
                    ),
                    probes: Vec::new(),
                    allow_alternate: true,
                };
                #[cfg(not(target_os = "android"))]
                let connection = if nelomai_contracts::allows_new_connection_intent_operation(
                    bootstrap.capabilities.as_ref(),
                    now_unix(),
                ) {
                    app.state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
                        .start_or_resume(options, now_unix())
                        .await?
                        .connection
                } else if skip_probe_refresh {
                    Some(
                        application
                            .start_without_probe_refresh(options, now_unix())
                            .await
                            .map_err(CommandError::from)?,
                    )
                } else {
                    Some(
                        application
                            .start(options, now_unix())
                            .await
                            .map_err(CommandError::from)?,
                    )
                };
                #[cfg(target_os = "android")]
                let connection = Some(if skip_probe_refresh {
                    application
                        .start_without_probe_refresh(options, now_unix())
                        .await
                        .map_err(CommandError::from)?
                } else {
                    application
                        .start(options, now_unix())
                        .await
                        .map_err(CommandError::from)?
                });
                #[cfg(desktop)]
                if let Some(connection) = &connection {
                    begin_desktop_tunnel_diagnostics(app, &connection.lease_id);
                }
                #[cfg(not(desktop))]
                let _ = connection;
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
    }
    let state = application.state().await;
    let warning = application.split_tunnel_warning().await;
    let metrics = app.state::<Arc<ConnectionMetricsTracker>>();
    let metrics_context = application.connection_metrics_context().await;
    let current_metrics = current_connection_metrics(&metrics, metrics_context.as_ref()).await;
    let (intent_status, next_retry_at_unix) = current_connection_intent(app).await;
    Ok(AppStateResponse::new(
        state,
        warning,
        current_metrics,
        intent_status,
        next_retry_at_unix,
    ))
}

#[tauri::command]
pub async fn app_login(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
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
    #[cfg(desktop)]
    diagnostics.set_automatic_device(&response.device.id);
    let _ = app.tunnel_android().clear_background();
    let _ = app.tunnel_android().clear_quick_plan();
    provision_android_background_resilient(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        response.device.id.clone(),
        response.capabilities.clone(),
    )
    .await;
    schedule_startup_split_tunnel_refresh(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
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
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    split_tunnel_scheduler: State<'_, Arc<SplitTunnelScheduler>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<Bootstrap, CommandError> {
    diagnostics.record_named("startup.bootstrap.begin", None, None, None);
    let bootstrap_started = Instant::now();
    let response = match tokio::time::timeout(
        STARTUP_BOOTSTRAP_TIMEOUT,
        bootstrap_application_for_startup(
            &app,
            application.inner(),
            diagnostics.inner(),
            now_unix(),
        ),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            diagnostics.record_timed_named(
                "startup.bootstrap.failed",
                None,
                None,
                Some(error.code()),
                bootstrap_started.elapsed(),
            );
            return Err(error);
        }
        Err(_) => {
            diagnostics.record_timed_named(
                "startup.bootstrap.failed",
                None,
                None,
                Some("startup_timeout"),
                bootstrap_started.elapsed(),
            );
            return Err(CommandError::new(
                "startup_timeout",
                "Не удалось завершить запуск вовремя. Проверьте сеть и повторите попытку",
            ));
        }
    };
    diagnostics.record_timed_named(
        "startup.bootstrap.ready",
        None,
        Some(&response.request_id),
        None,
        bootstrap_started.elapsed(),
    );
    #[cfg(desktop)]
    diagnostics.set_automatic_device(&response.device.id);
    schedule_startup_split_tunnel_refresh(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        split_tunnel_scheduler.inner().clone(),
    );
    schedule_android_background_provision(
        app.clone(),
        application.inner().clone(),
        diagnostics.inner().clone(),
        response.device.id.clone(),
        response.capabilities.clone(),
    );
    observe_and_schedule_update(
        application.inner().clone(),
        updater.inner().clone(),
        &response,
    );
    schedule_push_registration(
        app,
        application.inner().clone(),
        push_registration_scheduler.inner().clone(),
    );
    Ok(response)
}

#[tauri::command]
pub fn app_record_startup_stage(diagnostics: State<'_, Arc<AppDiagnostics>>, stage: StartupStage) {
    if matches!(&stage, StartupStage::FrontendFirstFrame) {
        diagnostics.mark_frontend_ready();
    }
    diagnostics.record_named(stage.event_name(), None, None, None);
}

async fn provision_android_background(
    app: &AppHandle,
    application: &NativeApplication,
    device_id: &str,
    capability: Option<&ConnectionIntentCapability>,
) -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    {
        let now = now_unix();
        let mut status = app
            .tunnel_android()
            .background_credential_status()
            .map_err(|_| {
                CommandError::new(
                    "background_storage_unavailable",
                    "Не удалось проверить фоновое подключение",
                )
            })?;
        let desired_capability_enabled =
            capability.is_some_and(|value| value.connection_intent_recovery_v1);
        let provision_with_ui_authentication =
            |expected_revision: i64| -> Result<(), CommandError> {
                let access_token = application
                    .current_access_token()
                    .map_err(CommandError::from)?;
                let install_secret = application.install_secret().map_err(CommandError::from)?;
                app.tunnel_android()
                    .provision_background(
                        tauri_plugin_tunnel_android::BackgroundUiProvisionRequest {
                            api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
                            expected_revision,
                            device_id: device_id.to_string(),
                            panel_base: crate::PANEL_BASE.to_string(),
                            access_token,
                            install_secret,
                            capability_revision: capability
                                .map(|value| i64::from(value.revision))
                                .unwrap_or(0),
                            capability_enabled: capability
                                .is_some_and(|value| value.connection_intent_recovery_v1),
                            capability_expires_at: capability
                                .map(|value| value.expires_at.clone())
                                .unwrap_or_else(|| "1970-01-01T00:00:01Z".to_string()),
                        },
                    )
                    .map_err(|_| {
                        CommandError::new(
                            "background_credential_provision_failed",
                            "Не удалось безопасно подготовить фоновое подключение",
                        )
                    })
            };
        match android_background_provision_mode(&status, device_id, desired_capability_enabled, now)
        {
            AndroidBackgroundProvisionMode::Noop => return Ok(()),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase => {
                let error = match provision_with_ui_authentication(status.credential_revision) {
                    Ok(()) => return Ok(()),
                    Err(error) => error,
                };
                let latest_status = app
                    .tunnel_android()
                    .background_credential_status()
                    .map_err(|_| {
                        CommandError::new(
                            "background_storage_unavailable",
                            "Не удалось повторно проверить фоновое подключение",
                        )
                    })?;
                if !android_background_legacy_fallback_after_ui_failure(
                    desired_capability_enabled,
                    &latest_status,
                ) {
                    return Err(error);
                }
                status = latest_status;
            }
            AndroidBackgroundProvisionMode::RefreshStoredCapability => {
                let refresh = app.tunnel_android().rotate_background(
                    tauri_plugin_tunnel_android::BackgroundCredentialMutationRequest {
                        expected_revision: status.credential_revision,
                    },
                );
                if refresh.is_ok() {
                    return Ok(());
                }
                if android_background_rotation_fallback(desired_capability_enabled).is_some() {
                    let latest_revision = app
                        .tunnel_android()
                        .background_credential_status()
                        .map_err(|_| {
                            CommandError::new(
                                "background_storage_unavailable",
                                "Не удалось повторно проверить фоновое подключение",
                            )
                        })?
                        .credential_revision;
                    return provision_with_ui_authentication(latest_revision);
                }
                return Err(CommandError::new(
                    "background_credential_rotation_failed",
                    "Не удалось обновить фоновое подключение",
                ));
            }
            AndroidBackgroundProvisionMode::Legacy => {}
        }
        let token = application
            .background_token_for_device(device_id, now)
            .await
            .map_err(CommandError::from)?
            .ok_or_else(|| {
                CommandError::new(
                    "background_device_changed",
                    "Учётная запись устройства изменилась",
                )
            })?;
        let expires_at_unix = now.saturating_add(token.expires_in.min(i64::MAX as u64) as i64);
        let install_secret = application.install_secret().map_err(CommandError::from)?;
        app.tunnel_android()
            .configure_background(tauri_plugin_tunnel_android::BackgroundCredentialRequest {
                api_version: tauri_plugin_tunnel_android::TUNNEL_API_VERSION,
                expected_revision: status.credential_revision,
                device_id: device_id.to_string(),
                panel_base: crate::PANEL_BASE.to_string(),
                token: token.token,
                expires_at_unix,
                install_secret,
                capability_revision: capability
                    .map(|value| i64::from(value.revision))
                    .unwrap_or(0),
                capability_enabled: capability
                    .is_some_and(|value| value.connection_intent_recovery_v1),
                capability_expires_at: capability
                    .map(|value| value.expires_at.clone())
                    .unwrap_or_else(|| "1970-01-01T00:00:01Z".to_string()),
            })
            .map_err(|_| {
                CommandError::new(
                    "background_storage_unavailable",
                    "Не удалось подготовить фоновое подключение",
                )
            })?;
    }
    #[cfg(not(target_os = "android"))]
    let _ = (app, application, device_id, capability);
    Ok(())
}

async fn provision_android_background_resilient(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    device_id: String,
    capability: Option<ConnectionIntentCapability>,
) {
    let Err(error) = provision_android_background_serialized(
        &app,
        &application,
        &device_id,
        capability.as_ref(),
    )
    .await
    else {
        return;
    };
    diagnostics.record_named(
        "background.provision_failed",
        None,
        None,
        Some(error.code()),
    );

    #[cfg(target_os = "android")]
    tauri::async_runtime::spawn(async move {
        for delay_seconds in [5, 30, 120] {
            tokio::time::sleep(std::time::Duration::from_secs(delay_seconds)).await;
            match provision_android_background_serialized(
                &app,
                &application,
                &device_id,
                capability.as_ref(),
            )
            .await
            {
                Ok(()) => {
                    diagnostics.record_named("background.provision_recovered", None, None, None);
                    return;
                }
                Err(error) => diagnostics.record_named(
                    "background.provision_retry_failed",
                    None,
                    None,
                    Some(error.code()),
                ),
            }
        }
    });

    #[cfg(not(target_os = "android"))]
    let _ = (app, application, device_id, capability);
}

fn schedule_android_background_provision(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    device_id: String,
    capability: Option<ConnectionIntentCapability>,
) {
    tauri::async_runtime::spawn(async move {
        provision_android_background_resilient(
            app,
            application,
            diagnostics,
            device_id,
            capability,
        )
        .await;
    });
}

async fn provision_android_background_serialized(
    app: &AppHandle,
    application: &NativeApplication,
    device_id: &str,
    capability: Option<&ConnectionIntentCapability>,
) -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    let _guard = ANDROID_BACKGROUND_PROVISION_GATE.lock().await;
    provision_android_background(app, application, device_id, capability).await
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
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<SafePeerBindingResponse, CommandError> {
    let response = application
        .unbind_peer()
        .await
        .map_err(CommandError::from)?;
    let _ = app.tunnel_android().clear_quick_plan();
    Ok(response.into())
}

#[tauri::command]
pub async fn app_refresh_probes(
    application: State<'_, Arc<NativeApplication>>,
    layer: Layer,
    egress_mode: EgressMode,
) -> Result<ProbeResults, CommandError> {
    application
        .refresh_probes(layer, egress_mode, now_unix())
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_prepare_tunnel(
    app: AppHandle,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    device_id: String,
) -> Result<(), CommandError> {
    match crate::platform::prepare_tunnel(app.clone()).await {
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
            schedule_start_failure_diagnostics(
                app,
                diagnostics.inner().clone(),
                tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                    device_id,
                    error_code: command_error.code().to_string(),
                },
            );
            Err(command_error)
        }
    }
}

#[tauri::command]
pub async fn app_windows_defender_status(
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<WindowsDefenderStatusResponse, CommandError> {
    #[cfg(windows)]
    {
        let status = crate::platform::windows::refresh_defender_status()
            .await
            .map_err(CommandError::from_tunnel)?;
        record_defender_status(&diagnostics, "windows.defender.checked", &status);
        Ok(defender_status_response(status))
    }
    #[cfg(not(windows))]
    {
        let _ = diagnostics;
        Ok(WindowsDefenderStatusResponse {
            supported: false,
            state: "not_applicable".to_string(),
            dll_present: false,
            dll_path: None,
            detail_code: None,
            antivirus_products: Vec::new(),
            antivirus_detail_code: None,
        })
    }
}

#[tauri::command]
pub async fn app_windows_defender_repair(
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<WindowsDefenderStatusResponse, CommandError> {
    #[cfg(windows)]
    {
        let status = match crate::platform::windows::repair_defender_exclusion().await {
            Ok(status) => status,
            Err(error) => {
                let error = CommandError::from_tunnel(error);
                diagnostics.record_named(
                    "windows.defender.repair_failed",
                    None,
                    None,
                    Some(error.code()),
                );
                return Err(error);
            }
        };
        record_defender_status(&diagnostics, "windows.defender.repaired", &status);
        Ok(defender_status_response(status))
    }
    #[cfg(not(windows))]
    {
        let _ = diagnostics;
        Err(CommandError::new(
            "defender_exclusion_unsupported",
            "Microsoft Defender доступен только в Windows",
        ))
    }
}

#[cfg(windows)]
fn defender_status_response(
    status: nelomai_windows_service::DefenderStatus,
) -> WindowsDefenderStatusResponse {
    WindowsDefenderStatusResponse {
        supported: true,
        state: defender_state_name(status.state).to_string(),
        dll_present: status.dll_present,
        dll_path: std::env::current_exe().ok().map(|path| {
            path.with_file_name("amneziawg-tunnel.dll")
                .display()
                .to_string()
        }),
        detail_code: status.detail_code,
        antivirus_products: status
            .antivirus_products
            .into_iter()
            .map(|product| WindowsAntivirusProductResponse {
                name: product.name,
                state: antivirus_product_state_name(product.state).to_string(),
                signatures_up_to_date: product.signatures_up_to_date,
                is_default: product.is_default,
                is_microsoft_defender: product.is_microsoft_defender,
            })
            .collect(),
        antivirus_detail_code: status.antivirus_detail_code,
    }
}

#[cfg(windows)]
fn record_defender_status(
    diagnostics: &AppDiagnostics,
    event: &str,
    status: &nelomai_windows_service::DefenderStatus,
) {
    let active_third_party = status
        .antivirus_products
        .iter()
        .filter(|product| {
            product.state == nelomai_windows_service::AntivirusProductState::On
                && !product.is_microsoft_defender
        })
        .count();
    let code = format!(
        "{}_dll_{}_{}_antivirus_{}_active_third_party_{}_{}",
        defender_state_name(status.state),
        if status.dll_present {
            "present"
        } else {
            "missing"
        },
        status.detail_code.as_deref().unwrap_or("ok"),
        status.antivirus_products.len(),
        active_third_party,
        status.antivirus_detail_code.as_deref().unwrap_or("ok")
    );
    diagnostics.record_named(event, None, None, Some(&code));
}

#[cfg(windows)]
fn antivirus_product_state_name(
    state: nelomai_windows_service::AntivirusProductState,
) -> &'static str {
    use nelomai_windows_service::AntivirusProductState;
    match state {
        AntivirusProductState::On => "on",
        AntivirusProductState::Off => "off",
        AntivirusProductState::Snoozed => "snoozed",
        AntivirusProductState::Expired => "expired",
        AntivirusProductState::Unknown => "unknown",
    }
}

#[cfg(windows)]
fn defender_state_name(state: nelomai_windows_service::DefenderExclusionState) -> &'static str {
    use nelomai_windows_service::DefenderExclusionState;
    match state {
        DefenderExclusionState::Excluded => "excluded",
        DefenderExclusionState::Missing => "missing",
        DefenderExclusionState::Inactive => "inactive",
        DefenderExclusionState::Unavailable => "unavailable",
    }
}

#[cfg(windows)]
async fn ensure_defender_ready_for_awg(diagnostics: &AppDiagnostics) -> Result<(), CommandError> {
    let defender = crate::platform::windows::defender_status()
        .await
        .map_err(CommandError::from_tunnel)?;
    record_defender_status(diagnostics, "windows.defender.before_awg_start", &defender);
    if !defender.dll_present {
        return Err(CommandError::from_tunnel(
            nelomai_client_tunnel::TunnelError::Backend("amneziawg_component_missing".to_string()),
        ));
    }
    if defender.state == nelomai_windows_service::DefenderExclusionState::Missing {
        return Err(CommandError::from_tunnel(
            nelomai_client_tunnel::TunnelError::Backend("defender_exclusion_missing".to_string()),
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn app_start(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    request: StartCommandRequest,
) -> Result<StartCommandResponse, CommandError> {
    let device_id = request.device_id;
    let start_result = async {
        #[cfg(windows)]
        if request.layer == Layer::Stray {
            ensure_defender_ready_for_awg(&diagnostics).await?;
        }
        refresh_installed_applications_before_start(
            &app,
            &application,
            request.layer,
            request.route_mode,
        )
        .await?;
        let options = ConnectOptions {
            layer: request.layer,
            tic_connection_mode: request.tic_connection_mode,
            route_mode: request.route_mode,
            egress_mode: request.egress_mode,
            probes: Vec::new(),
            allow_alternate: request.allow_alternate,
        };
        #[cfg(not(target_os = "android"))]
        {
            use tauri::Manager;

            let now = now_unix();
            let bootstrap = application
                .bootstrap(now)
                .await
                .map_err(CommandError::from)?;
            if bootstrap.device.id != device_id {
                return Err(CommandError::new(
                    "device_mismatch",
                    "Подключение запрошено для другого устройства",
                ));
            }
            let runtime = app
                .state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
                .inner()
                .clone();
            if runtime.snapshot().await.status != nelomai_client_core::ConnectionIntentStatus::None
                || nelomai_contracts::allows_new_connection_intent_operation(
                    bootstrap.capabilities.as_ref(),
                    now,
                )
            {
                return runtime.start_or_resume(options, now).await;
            }
            application
                .start(options, now)
                .await
                .map(StartCommandResponse::connected)
                .map_err(CommandError::from)
        }
        #[cfg(target_os = "android")]
        {
            application
                .start(options, now_unix())
                .await
                .map(StartCommandResponse::connected)
                .map_err(CommandError::from)
        }
    }
    .await;
    match start_result {
        Ok(response) => {
            #[cfg(desktop)]
            if let Some(connection) = &response.connection {
                begin_desktop_tunnel_diagnostics(&app, &connection.lease_id);
            }
            Ok(response)
        }
        Err(command_error) => {
            schedule_start_failure_diagnostics(
                app,
                diagnostics.inner().clone(),
                tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                    device_id,
                    error_code: command_error.code().to_string(),
                },
            );
            Err(command_error)
        }
    }
}

#[tauri::command]
pub async fn app_queue_start_failure_diagnostics(
    app: AppHandle,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    device_id: String,
    error_code: String,
) -> Result<(), CommandError> {
    app.tunnel_android()
        .queue_start_failure_diagnostics_async(
            tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest {
                device_id,
                error_code,
            },
        )
        .await
        .map_err(|_| {
            diagnostics.record_named(
                "diagnostics.start_failure_enqueue_failed",
                None,
                None,
                Some("diagnostics_storage_unavailable"),
            );
            CommandError::new(
                "diagnostics_storage_unavailable",
                "Не удалось сохранить автоматический отчёт",
            )
        })
}

fn schedule_start_failure_diagnostics(
    app: AppHandle,
    diagnostics: Arc<AppDiagnostics>,
    request: tauri_plugin_tunnel_android::StartFailureDiagnosticsRequest,
) {
    #[cfg(target_os = "android")]
    tauri::async_runtime::spawn(async move {
        if app
            .tunnel_android()
            .queue_start_failure_diagnostics_async(request)
            .await
            .is_err()
        {
            diagnostics.record_named(
                "diagnostics.start_failure_enqueue_failed",
                None,
                None,
                Some("diagnostics_storage_unavailable"),
            );
        }
    });

    #[cfg(not(target_os = "android"))]
    let _ = (app, diagnostics, request);
}

#[tauri::command]
pub async fn app_start_saved_stray(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    diagnostics: State<'_, Arc<AppDiagnostics>>,
) -> Result<String, CommandError> {
    #[cfg(windows)]
    ensure_defender_ready_for_awg(&diagnostics).await?;
    #[cfg(not(windows))]
    let _ = &diagnostics;
    refresh_installed_applications_before_start(
        &app,
        &application,
        Layer::Stray,
        RouteMode::Standalone,
    )
    .await?;
    let session_id = application
        .start_saved_stray_offline(now_unix())
        .await
        .map_err(CommandError::from)?;
    #[cfg(desktop)]
    begin_desktop_tunnel_diagnostics(&app, &session_id);
    Ok(session_id)
}

#[tauri::command]
pub async fn app_stop(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Option<Connection>, CommandError> {
    stop_connection(&app, &application).await
}

#[tauri::command]
pub async fn app_wake_connection_intent(app: AppHandle) -> Result<(), CommandError> {
    #[cfg(not(target_os = "android"))]
    {
        use tauri::Manager;

        app.state::<Arc<crate::connection_intent::DesktopConnectionIntent>>()
            .wake_for_network_change()
            .await;
    }
    #[cfg(target_os = "android")]
    let _ = app;
    Ok(())
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
    tunnel: State<'_, Arc<crate::platform::PlatformTunnelController>>,
) -> Result<DiagnosticUploadResponse, CommandError> {
    let connection_before = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let resource_snapshot = crate::resource_usage::ResourceSnapshot::capture(&app);
    #[cfg(desktop)]
    let helper_log = crate::platform::diagnostic_helper_log(&tunnel).await;
    #[cfg(not(desktop))]
    let helper_log = {
        let _ = &tunnel;
        None
    };
    let connection_after = application
        .connection_metrics_context()
        .await
        .map(|context| context.session_id);
    let connection_lease_id =
        stable_diagnostics_connection_lease(connection_before, connection_after);
    let report = diagnostics
        .build_report_with_helper(
            resource_snapshot,
            helper_log,
            connection_lease_id.as_deref(),
        )
        .map_err(|_| {
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

fn stable_diagnostics_connection_lease(
    before: Option<String>,
    after: Option<String>,
) -> Option<String> {
    match (before, after) {
        (Some(before), Some(after)) if before == after => Some(before),
        _ => None,
    }
}

#[tauri::command]
pub fn app_update_status(
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    updater.status().map_err(update_command_error)
}

#[tauri::command]
pub async fn app_update_refresh(
    application: State<'_, Arc<NativeApplication>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<UpdateStatusResponse, CommandError> {
    let Some(_refresh_guard) = updater.try_begin_refresh() else {
        return updater.status().map_err(update_command_error);
    };
    let update = application
        .refresh_update_state()
        .await
        .map_err(CommandError::from)?;
    updater.observe(&update).map_err(update_command_error)?;
    if updater.automatic_enabled().map_err(update_command_error)? {
        schedule_automatic_update(application.inner().clone(), updater.inner().clone());
    }
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
pub async fn app_update_restart(
    app: AppHandle,
    application: State<'_, Arc<NativeApplication>>,
    updater: State<'_, Arc<NativeUpdater>>,
) -> Result<(), CommandError> {
    if !updater.ready_to_restart() {
        return Err(CommandError::new(
            "update_not_ready",
            "Обновление ещё не готово к перезапуску",
        ));
    }
    stop_for_shutdown(&app, &application).await?;
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
    diagnostics: State<'_, Arc<AppDiagnostics>>,
    push_registration_scheduler: State<'_, Arc<PushRegistrationScheduler>>,
) -> Result<(), CommandError> {
    cancel_desktop_connection_intent(&app).await;
    #[cfg(desktop)]
    prepare_desktop_logout(&app, &application, &diagnostics).await;
    let logout_result = push_registration_scheduler.logout(&app, &application).await;
    let quick_plan_result = app.tunnel_android().clear_quick_plan();
    let background_result = app.tunnel_android().clear_background();

    if let Err(error) = logout_result {
        return Err(CommandError::from(error));
    }
    #[cfg(desktop)]
    diagnostics.clear_automatic_device();
    #[cfg(not(desktop))]
    let _ = &diagnostics;
    quick_plan_result.map_err(|_| {
        CommandError::new(
            "quick_state_persist_failed",
            "Не удалось очистить данные быстрого подключения",
        )
    })?;
    background_result.map_err(|_| {
        CommandError::new(
            "background_storage_unavailable",
            "Не удалось очистить данные фонового подключения",
        )
    })?;
    Ok(())
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

fn schedule_startup_split_tunnel_refresh(
    app: AppHandle,
    application: Arc<NativeApplication>,
    diagnostics: Arc<AppDiagnostics>,
    scheduler: Arc<SplitTunnelScheduler>,
) {
    tauri::async_runtime::spawn(async move {
        #[cfg(target_os = "android")]
        {
            diagnostics.record_named("startup.application_inventory.scheduled", None, None, None);
            let inventory_app = app.clone();
            let inventory_application = application.clone();
            let inventory_diagnostics = diagnostics.clone();
            let inventory_refreshed = match tauri::async_runtime::spawn_blocking(move || {
                let started = Instant::now();
                match refresh_installed_applications(&inventory_app, &inventory_application) {
                    Ok(applications) => {
                        inventory_diagnostics.record_timed_named(
                            "startup.application_inventory.completed",
                            None,
                            None,
                            Some(&format!("applications={}", applications.len())),
                            started.elapsed(),
                        );
                        true
                    }
                    Err(error) => {
                        inventory_diagnostics.record_timed_named(
                            "startup.application_inventory.failed",
                            None,
                            None,
                            Some(error.code()),
                            started.elapsed(),
                        );
                        false
                    }
                }
            })
            .await
            {
                Ok(refreshed) => refreshed,
                Err(_) => {
                    diagnostics.record_named(
                        "startup.application_inventory.failed",
                        None,
                        None,
                        Some("worker_unavailable"),
                    );
                    false
                }
            };
            if !inventory_refreshed {
                return;
            }
        }
        #[cfg(not(target_os = "android"))]
        let _ = (app, diagnostics);
        let _ = scheduler.synchronize(&application, false).await;
    });
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
    fn manual_diagnostics_uses_only_an_unchanged_connection_lease() {
        assert_eq!(
            stable_diagnostics_connection_lease(
                Some("lease-1".to_string()),
                Some("lease-1".to_string()),
            ),
            Some("lease-1".to_string()),
        );
        assert_eq!(
            stable_diagnostics_connection_lease(
                Some("lease-1".to_string()),
                Some("lease-2".to_string()),
            ),
            None,
        );
        assert_eq!(
            stable_diagnostics_connection_lease(Some("lease-1".to_string()), None),
            None,
        );
        assert_eq!(
            stable_diagnostics_connection_lease(None, Some("lease-1".to_string())),
            None,
        );
    }

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
    fn connection_intent_state_projection_masks_only_recovering_as_connecting() {
        let recovering = AppStateResponse::new(
            CoreState {
                phase: Phase::ServerUnavailable,
                connection: None,
            },
            None,
            None,
            nelomai_client_core::ConnectionIntentStatus::Recovering,
            Some(1_700_000_123),
        );
        let value = serde_json::to_value(recovering).unwrap();
        assert_eq!(value["phase"], "connecting");
        assert_eq!(value["connectionIntentStatus"], "recovering");
        assert_eq!(value["nextRetryAtUnix"], 1_700_000_123_i64);

        let blocked = AppStateResponse::new(
            CoreState {
                phase: Phase::Error,
                connection: None,
            },
            None,
            None,
            nelomai_client_core::ConnectionIntentStatus::BlockedTerminal,
            None,
        );
        let value = serde_json::to_value(blocked).unwrap();
        assert_eq!(value["phase"], "error");
        assert_eq!(value["connectionIntentStatus"], "blocked_terminal");
        assert!(value["nextRetryAtUnix"].is_null());
    }

    #[test]
    fn connection_intent_start_response_distinguishes_recovery_from_success() {
        let value = serde_json::to_value(StartCommandResponse::recovering(Some(42))).unwrap();
        assert_eq!(value["status"], "recovering");
        assert!(value["connection"].is_null());
        assert_eq!(value["nextRetryAtUnix"], 42);
    }

    #[test]
    fn shutdown_stops_a_blocked_connection_even_after_core_enters_error() {
        assert!(shutdown_requires_stop(
            &CoreState {
                phase: Phase::Error,
                connection: None,
            },
            true,
        ));
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

        let endpoint =
            CommandError::from_core(CoreError::Tunnel("endpoint_route_lost".to_string()));
        assert_eq!(endpoint.code, "endpoint_route_lost");
        assert!(endpoint.message.contains("остановлен для защиты"));

        let handshake =
            CommandError::from_core(CoreError::Tunnel("tunnel_handshake_timeout".to_string()));
        assert_eq!(handshake.code, "tunnel_handshake_timeout");
        assert!(handshake.message.contains("Stray-сервер"));
    }

    #[test]
    fn split_tunnel_stop_failure_keeps_its_actionable_error() {
        let error = CommandError::from_core(CoreError::SplitTunnel(
            "split_tunnel_stop_failed".to_string(),
        ));

        assert_eq!(error.code, "split_tunnel_stop_failed");
        assert!(error.message.contains("остановить подключение"));
    }

    #[test]
    fn tunnel_service_failures_are_repairable_before_stop_retry() {
        for code in [
            "service_unavailable",
            "service_outdated",
            "udp_rebind_failed",
            "udp_rebind_timeout",
            "service_stopping",
            "unsupported_protocol",
            "unauthorized_client",
            "truncated_frame",
            "missing_service_version",
        ] {
            let error = ApplicationError::Core(CoreError::Tunnel(code.to_string()));
            assert!(repairable_stop_error(&error), "{code}");
        }
        let route_error = ApplicationError::Core(CoreError::Tunnel("route_conflict".to_string()));
        assert!(!repairable_stop_error(&route_error));
    }

    #[test]
    fn udp_rebind_failures_keep_the_service_recovery_message() {
        for code in ["udp_rebind_failed", "udp_rebind_timeout"] {
            let error = CommandError::from_core(CoreError::Tunnel(code.to_string()));

            assert_eq!(error.code, "tunnel_service_unavailable", "{code}");
            assert!(error.message.contains("Повторите действие"), "{code}");
        }
    }

    #[test]
    fn startup_diagnostics_accept_only_known_frontend_stages() {
        let stage: StartupStage = serde_json::from_str("\"frontend_first_frame\"").unwrap();
        assert_eq!(stage.event_name(), "startup.frontend.first_frame");
        assert!(serde_json::from_str::<StartupStage>("\"arbitrary_event\"").is_err());
    }

    #[test]
    fn background_recovery_is_limited_to_a_configured_signed_out_android_session() {
        assert!(should_attempt_android_background_recovery(
            &ApplicationError::Core(CoreError::SignedOut),
            true,
        ));
        assert!(!should_attempt_android_background_recovery(
            &ApplicationError::Core(CoreError::SignedOut),
            false,
        ));
        assert!(!should_attempt_android_background_recovery(
            &ApplicationError::Core(CoreError::Api(CoreApiError::Retryable)),
            true,
        ));
    }

    #[test]
    fn invalid_background_recovery_falls_back_but_missing_route_keeps_the_credential() {
        assert_eq!(
            classify_android_background_recovery_error("invalid_background_token"),
            AndroidBackgroundRecoveryFailure::ClearAndFallbackRefresh,
        );
        assert_eq!(
            classify_android_background_recovery_error("invalid_background_recovery"),
            AndroidBackgroundRecoveryFailure::ClearAndFallbackRefresh,
        );
        assert_eq!(
            classify_android_background_recovery_error("background_recovery_unsupported"),
            AndroidBackgroundRecoveryFailure::FallbackRefresh,
        );
        assert_eq!(
            classify_android_background_recovery_error("activation_not_applied"),
            AndroidBackgroundRecoveryFailure::FallbackRefresh,
        );
        assert_eq!(
            classify_android_background_recovery_error("background_transport_unavailable"),
            AndroidBackgroundRecoveryFailure::Retryable,
        );
    }

    #[test]
    fn unavailable_application_access_is_terminal_instead_of_a_network_retry() {
        assert_eq!(
            classify_android_background_recovery_error("app_access_unavailable"),
            AndroidBackgroundRecoveryFailure::AccessExpired,
        );
    }

    #[test]
    fn enabled_recovery_with_an_expired_device_token_uses_ui_authenticated_provision() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 7,
            mutation_ready: true,
            mutation_pending: false,
            capability_enabled: true,
            capability_expires_at_unix: Some(200),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(100),
        };

        assert_eq!(
            android_background_provision_mode(&status, "device-1", true, 150),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase,
        );
    }

    #[test]
    fn pending_activation_is_replayed_even_while_the_old_local_token_looks_fresh() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 8,
            mutation_ready: true,
            mutation_pending: true,
            capability_enabled: true,
            capability_expires_at_unix: Some(300),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };

        assert_eq!(
            android_background_provision_mode(&status, "device-1", true, 150),
            AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase,
        );
    }

    #[test]
    fn expired_capability_with_a_fresh_device_token_only_refreshes_the_snapshot() {
        let status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            configured: true,
            credential_revision: 9,
            mutation_ready: true,
            mutation_pending: false,
            capability_enabled: true,
            capability_expires_at_unix: Some(100),
            device_id: Some("device-1".to_string()),
            expires_at_unix: Some(2_000_000),
        };

        assert_eq!(
            android_background_provision_mode(&status, "device-1", true, 150),
            AndroidBackgroundProvisionMode::RefreshStoredCapability,
        );
    }

    #[test]
    fn failed_device_refresh_uses_available_ui_authentication_only_for_enabled_recovery() {
        assert_eq!(
            android_background_rotation_fallback(true),
            Some(AndroidBackgroundProvisionMode::UiAuthenticatedTwoPhase),
        );
        assert_eq!(android_background_rotation_fallback(false), None);
    }

    #[test]
    fn capability_downgrade_returns_to_legacy_only_after_the_journal_is_clear() {
        let mut status = tauri_plugin_tunnel_android::BackgroundCredentialStatusResponse {
            mutation_pending: true,
            ..Default::default()
        };
        assert!(!android_background_legacy_fallback_after_ui_failure(
            false, &status,
        ));

        status.mutation_pending = false;
        assert!(android_background_legacy_fallback_after_ui_failure(
            false, &status,
        ));
        assert!(!android_background_legacy_fallback_after_ui_failure(
            true, &status,
        ));
    }

    #[tokio::test]
    async fn outer_timeout_does_not_cancel_a_detached_mobile_operation() {
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let operation = await_detached_on_cancellation(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = completed_tx.send(());
            42
        });

        assert!(tokio::time::timeout(Duration::from_millis(1), operation)
            .await
            .is_err());
        tokio::time::timeout(Duration::from_secs(1), completed_rx)
            .await
            .unwrap()
            .unwrap();
    }
}
