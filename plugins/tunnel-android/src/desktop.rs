use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<TunnelAndroid<R>> {
    Ok(TunnelAndroid(app.clone()))
}

/// Access to the tunnel-android APIs.
pub struct TunnelAndroid<R: Runtime>(AppHandle<R>);

impl<R: Runtime> TunnelAndroid<R> {
    pub fn probe(&self) -> crate::Result<ProbeResponse> {
        Ok(ProbeResponse {
            platform: std::env::consts::OS.to_string(),
            android_api_level: None,
            address_split_tunnel: false,
            application_split_tunnel: false,
            backend_available: false,
            permission_granted: false,
            backend_version: None,
            error: Some("Android WireGuard backend is unavailable on desktop".to_string()),
        })
    }

    pub fn request_vpn_permission(&self) -> crate::Result<PermissionResponse> {
        Ok(PermissionResponse {
            permission_granted: false,
        })
    }

    pub fn installed_applications(&self) -> crate::Result<InstalledApplicationsResponse> {
        Ok(InstalledApplicationsResponse::default())
    }

    pub fn resource_usage(&self) -> crate::Result<ResourceUsageResponse> {
        Ok(ResourceUsageResponse::default())
    }

    pub fn take_quick_action(&self) -> crate::Result<bool> {
        Ok(false)
    }

    pub fn refresh_quick_tile(&self, _success: bool) -> crate::Result<()> {
        Ok(())
    }

    pub fn start_tunnel(
        &self,
        _request: StartTunnelRequest,
    ) -> crate::Result<TunnelOperationResponse> {
        Ok(unsupported_response())
    }

    pub fn stop_tunnel(&self) -> crate::Result<TunnelOperationResponse> {
        Ok(unsupported_response())
    }

    pub fn tunnel_status(&self) -> crate::Result<TunnelOperationResponse> {
        Ok(unsupported_response())
    }
    pub fn tunnel_metrics(&self, _probe: bool) -> crate::Result<TunnelMetricsResponse> {
        Ok(TunnelMetricsResponse::default())
    }
}

fn unsupported_response() -> TunnelOperationResponse {
    TunnelOperationResponse {
        state: "unsupported".to_string(),
        duration_millis: 0,
        error_code: Some("android_tunnel_unavailable".to_string()),
    }
}
