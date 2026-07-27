use crate::NativeApplication;
use nelomai_client_application::{ApplicationError, LoginParameters};
use nelomai_client_core::{ConnectOptions, CoreApiError, CoreError, CoreState, Phase};
use nelomai_contracts::{
    BindPeerRequest, Bootstrap, Connection, Layer, PeerBinding, PeerBindingResponse, PeerOptions,
    Platform, ProbeResults, RouteMode, TicConnectionMode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};

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
                _ => Self::new("tunnel_failed", "Не удалось изменить состояние подключения"),
            },
        }
    }

    fn from_tunnel(error: nelomai_client_tunnel::TunnelError) -> Self {
        let nelomai_client_tunnel::TunnelError::Backend(code) = error;
        match code.as_str() {
            "vpn_permission_denied" => Self::new(
                "vpn_permission_denied",
                "Без разрешения Android подключение невозможно",
            ),
            "tunnel_backend_unavailable" => Self::new(
                "tunnel_backend_unavailable",
                "Система подключения недоступна на этом устройстве",
            ),
            "service_unavailable" | "service_outdated" => Self::new(
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
            _ => Self::new(
                "tunnel_failed",
                "Не удалось запустить подключение на устройстве",
            ),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateResponse {
    phase: &'static str,
    connection: Option<Connection>,
}

impl From<CoreState> for AppStateResponse {
    fn from(state: CoreState) -> Self {
        Self {
            phase: phase_name(state.phase),
            connection: state.connection,
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
    Ok(application.state().await.into())
}

#[tauri::command]
pub async fn app_login(
    application: State<'_, Arc<NativeApplication>>,
    request: LoginCommandRequest,
) -> Result<Bootstrap, CommandError> {
    application
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
        .map_err(Into::into)
}

#[tauri::command]
pub async fn app_bootstrap(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<Bootstrap, CommandError> {
    application.bootstrap(now_unix()).await.map_err(Into::into)
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
pub async fn app_prepare_tunnel(app: AppHandle) -> Result<(), CommandError> {
    crate::platform::prepare_tunnel(app)
        .await
        .map_err(CommandError::from_tunnel)
}

#[tauri::command]
pub async fn app_start(
    application: State<'_, Arc<NativeApplication>>,
    request: StartCommandRequest,
) -> Result<Connection, CommandError> {
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
    application: State<'_, Arc<NativeApplication>>,
) -> Result<String, CommandError> {
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
pub async fn app_logout(
    application: State<'_, Arc<NativeApplication>>,
) -> Result<(), CommandError> {
    application.logout().await.map_err(Into::into)
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
}
