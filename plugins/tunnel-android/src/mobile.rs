use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

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

    pub fn start_smoke_tunnel(&self) -> crate::Result<SmokeResponse> {
        self.0
            .run_mobile_plugin("startSmokeTunnel", SmokeRequest::default())
            .map_err(Into::into)
    }

    pub fn stop_smoke_tunnel(&self) -> crate::Result<SmokeResponse> {
        self.0
            .run_mobile_plugin("stopSmokeTunnel", SmokeRequest::default())
            .map_err(Into::into)
    }

    pub fn smoke_tunnel_status(&self) -> crate::Result<SmokeResponse> {
        self.0
            .run_mobile_plugin("smokeTunnelStatus", SmokeRequest::default())
            .map_err(Into::into)
    }
}
