use async_trait::async_trait;
use nelomai_client_tunnel::{
    QuickReconnect, TunnelCapabilities, TunnelController, TunnelError, TunnelMetrics,
    TunnelPlatform, TunnelStartRequest, TunnelStatus,
};
use nelomai_contracts::{Layer, RouteMode, SplitTunnelMode, TicConnectionMode};
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
            commands::installed_applications,
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
    async fn start(&self, request: TunnelStartRequest) -> std::result::Result<(), TunnelError> {
        request
            .options
            .validate()
            .map_err(|error| TunnelError::InvalidOptions {
                code: error.stable_code(),
            })?;
        let mut plugin_request = StartTunnelRequest::new(request.configuration.as_bytes());
        plugin_request.options.split_active = request.options.policy_hash.is_some();
        match request.options.application_mode {
            Some(SplitTunnelMode::ExcludeSelected) => {
                plugin_request.options.excluded_packages = request.options.package_ids;
            }
            Some(SplitTunnelMode::IncludeSelected) => {
                plugin_request.options.included_packages = request.options.package_ids;
            }
            None => {}
        }
        plugin_request.options.split_tunnel_routes = request.options.excluded_ipv4_cidrs;
        plugin_request.options.exclude_local_networks = request.options.exclude_local_networks;
        match request.quick_reconnect {
            QuickReconnect::Disabled => {}
            QuickReconnect::Persistent => {
                plugin_request.cache_quick_action = true;
            }
            QuickReconnect::Until(valid_until_unix) => {
                plugin_request.cache_quick_action = true;
                plugin_request.quick_action_valid_until_unix = Some(valid_until_unix);
            }
        }
        plugin_request.quick_connection =
            request
                .quick_connection
                .map(|quick| QuickConnectionRequest {
                    lease_id: quick.lease_id,
                    layer: match quick.layer {
                        Layer::Tic => "tic",
                        Layer::Stray => "stray",
                    }
                    .to_string(),
                    tic_connection_mode: match quick.tic_connection_mode {
                        TicConnectionMode::Personal => "personal",
                        TicConnectionMode::Dynamic => "dynamic",
                    }
                    .to_string(),
                    route_mode: match quick.route_mode {
                        RouteMode::Standalone => "standalone",
                        RouteMode::ViaTak => "via_tak",
                    }
                    .to_string(),
                    allow_alternate: quick.allow_alternate,
                });

        let response = self
            .app
            .tunnel_android()
            .start_tunnel(plugin_request)
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

    async fn metrics(
        &self,
        probe: bool,
    ) -> std::result::Result<Option<TunnelMetrics>, TunnelError> {
        let response = self
            .app
            .tunnel_android()
            .tunnel_metrics(probe)
            .map_err(to_tunnel_error)?;
        Ok(Some(TunnelMetrics {
            received_bytes: response.received_bytes,
            sent_bytes: response.sent_bytes,
            probe_target: response.probe_target,
        }))
    }

    async fn capabilities(&self) -> std::result::Result<TunnelCapabilities, TunnelError> {
        let probe = self.app.tunnel_android().probe().map_err(to_tunnel_error)?;
        Ok(TunnelCapabilities {
            platform: TunnelPlatform::Android,
            android_api_level: probe.android_api_level,
            address_split_tunnel: probe.address_split_tunnel,
            application_split_tunnel: probe.application_split_tunnel,
        })
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
