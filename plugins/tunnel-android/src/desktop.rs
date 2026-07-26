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

    pub fn start_smoke_tunnel(&self) -> crate::Result<SmokeResponse> {
        Ok(SmokeResponse {
            state: "unsupported".to_string(),
            duration_millis: 0,
        })
    }

    pub fn stop_smoke_tunnel(&self) -> crate::Result<SmokeResponse> {
        self.start_smoke_tunnel()
    }

    pub fn smoke_tunnel_status(&self) -> crate::Result<SmokeResponse> {
        self.start_smoke_tunnel()
    }
}
