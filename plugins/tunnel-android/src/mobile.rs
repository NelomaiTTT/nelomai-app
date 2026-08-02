use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EmptyRequest {}

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_tunnel_android);

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<TunnelAndroid<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("ru.nelomai.tunnel", "TunnelPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_tunnel_android)?;
    Ok(TunnelAndroid(handle))
}

/// Access to the tunnel-android APIs.
pub struct TunnelAndroid<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> TunnelAndroid<R> {
    pub fn probe(&self) -> crate::Result<ProbeResponse> {
        self.0
            .run_mobile_plugin("probe", ProbeRequest::default())
            .map_err(Into::into)
    }

    pub fn request_vpn_permission(&self) -> crate::Result<PermissionResponse> {
        self.0
            .run_mobile_plugin("requestVpnPermission", PermissionRequest::default())
            .map_err(Into::into)
    }

    pub fn installed_applications(&self) -> crate::Result<InstalledApplicationsResponse> {
        self.0
            .run_mobile_plugin(
                "installedApplications",
                InstalledApplicationsRequest::default(),
            )
            .map_err(Into::into)
    }

    pub fn resource_usage(&self) -> crate::Result<ResourceUsageResponse> {
        self.0
            .run_mobile_plugin("resourceUsage", ResourceUsageRequest::default())
            .map_err(Into::into)
    }

    pub fn take_quick_action(&self) -> crate::Result<bool> {
        self.0
            .run_mobile_plugin::<QuickActionResponse>("takeQuickAction", EmptyRequest {})
            .map(|response| response.pending)
            .map_err(Into::into)
    }

    pub fn refresh_quick_tile(&self, success: bool) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("refreshQuickTile", CompleteQuickActionRequest { success })
            .map_err(Into::into)
    }

    pub fn start_tunnel(
        &self,
        request: StartTunnelRequest,
    ) -> crate::Result<TunnelOperationResponse> {
        self.0
            .run_mobile_plugin("startTunnel", request)
            .map_err(Into::into)
    }

    pub fn stop_tunnel(&self) -> crate::Result<TunnelOperationResponse> {
        self.0
            .run_mobile_plugin(
                "stopTunnel",
                StopTunnelRequest {
                    api_version: TUNNEL_API_VERSION,
                },
            )
            .map_err(Into::into)
    }

    pub fn tunnel_status(&self) -> crate::Result<TunnelOperationResponse> {
        self.0
            .run_mobile_plugin(
                "tunnelStatus",
                TunnelStatusRequest {
                    api_version: TUNNEL_API_VERSION,
                },
            )
            .map_err(Into::into)
    }

    pub fn tunnel_metrics(&self, probe: bool) -> crate::Result<TunnelMetricsResponse> {
        self.0
            .run_mobile_plugin(
                "tunnelMetrics",
                TunnelMetricsRequest {
                    api_version: TUNNEL_API_VERSION,
                    probe,
                },
            )
            .map_err(Into::into)
    }
}
