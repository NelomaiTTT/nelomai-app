use async_trait::async_trait;
use nelomai_client_tunnel::{TunnelConfiguration, TunnelController, TunnelError, TunnelStatus};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::TunnelAndroid;
#[cfg(mobile)]
use mobile::TunnelAndroid;

/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the tunnel-android APIs.
pub trait TunnelAndroidExt<R: Runtime> {
    fn tunnel_android(&self) -> &TunnelAndroid<R>;
}

impl<R: Runtime, T: Manager<R>> crate::TunnelAndroidExt<R> for T {
    fn tunnel_android(&self) -> &TunnelAndroid<R> {
        self.state::<TunnelAndroid<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("tunnel-android")
        .invoke_handler(tauri::generate_handler![
            commands::probe,
            commands::request_vpn_permission,
            commands::tunnel_status
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let tunnel_android = mobile::init(app, api)?;
            #[cfg(desktop)]
            let tunnel_android = desktop::init(app, api)?;
            app.manage(tunnel_android);
            Ok(())
        })
        .build()
}

pub struct AndroidTunnelController<R: Runtime> {
    app: tauri::AppHandle<R>,
}

impl<R: Runtime> AndroidTunnelController<R> {
    pub fn new(app: tauri::AppHandle<R>) -> Self {
        Self { app }
    }
}

#[async_trait]
impl<R: Runtime> TunnelController for AndroidTunnelController<R> {
    async fn start(
        &self,
        configuration: TunnelConfiguration,
    ) -> std::result::Result<(), TunnelError> {
        let response = self
            .app
            .tunnel_android()
            .start_tunnel(StartTunnelRequest::new(configuration.as_bytes()))
            .map_err(to_tunnel_error)?;
        require_state(response, "running")
    }

    async fn stop(&self) -> std::result::Result<(), TunnelError> {
        let response = self
            .app
            .tunnel_android()
            .stop_tunnel()
            .map_err(to_tunnel_error)?;
        require_state(response, "stopped")
    }

    async fn status(&self) -> std::result::Result<TunnelStatus, TunnelError> {
        let response = self
            .app
            .tunnel_android()
            .tunnel_status()
            .map_err(to_tunnel_error)?;
        match response.state.as_str() {
            "stopped" => Ok(TunnelStatus::Stopped),
            "starting" => Ok(TunnelStatus::Starting),
            "running" => Ok(TunnelStatus::Running),
            "stopping" => Ok(TunnelStatus::Stopping),
            "failed" => Ok(TunnelStatus::Failed),
            state => Err(TunnelError::Backend(format!(
                "unknown Android tunnel state: {state}"
            ))),
        }
    }
}

fn require_state(
    response: TunnelOperationResponse,
    expected: &str,
) -> std::result::Result<(), TunnelError> {
    if response.state == expected {
        Ok(())
    } else {
        Err(TunnelError::Backend(response.error_code.unwrap_or_else(
            || format!("unexpected Android tunnel state: {}", response.state),
        )))
    }
}

fn to_tunnel_error(error: Error) -> TunnelError {
    TunnelError::Backend(error.to_string())
}
