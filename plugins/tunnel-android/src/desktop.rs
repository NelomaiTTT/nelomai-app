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

    pub fn clear_quick_plan(&self) -> crate::Result<()> {
        Ok(())
    }

    pub fn update_quick_dns(&self, _request: DnsServersRequest) -> crate::Result<()> {
        Ok(())
    }

    pub async fn queue_start_failure_diagnostics_async(
        &self,
        _request: StartFailureDiagnosticsRequest,
    ) -> crate::Result<()> {
        Ok(())
    }

    pub async fn update_quick_dns_async(&self, _request: DnsServersRequest) -> crate::Result<()> {
        Ok(())
    }

    pub fn configure_background(&self, _request: BackgroundCredentialRequest) -> crate::Result<()> {
        Ok(())
    }

    pub fn rotate_background(
        &self,
        _request: BackgroundCredentialMutationRequest,
    ) -> crate::Result<()> {
        Ok(())
    }

    pub fn background_credential_status(
        &self,
    ) -> crate::Result<BackgroundCredentialStatusResponse> {
        Ok(BackgroundCredentialStatusResponse::default())
    }

    pub fn clear_background(&self) -> crate::Result<()> {
        Ok(())
    }

    pub async fn recover_background_session(
        &self,
        _request: BackgroundSessionRecoveryRequest,
    ) -> crate::Result<BackgroundSessionRecoveryResponse> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Android background session recovery is unavailable on desktop",
        )
        .into())
    }

    pub fn take_quick_state_change(&self) -> crate::Result<QuickStateChangeResponse> {
        Ok(QuickStateChangeResponse::default())
    }

    pub fn acknowledge_quick_state_change(&self, _revision: u64) -> crate::Result<()> {
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
    pub async fn tunnel_status_async(&self) -> crate::Result<TunnelOperationResponse> {
        self.tunnel_status()
    }
    pub async fn tunnel_metrics_async(&self, _probe: bool) -> crate::Result<TunnelMetricsResponse> {
        Ok(TunnelMetricsResponse::default())
    }
    pub async fn tunnel_rebind_udp_async(&self) -> crate::Result<TunnelOperationResponse> {
        Ok(unsupported_response())
    }
}

fn unsupported_response() -> TunnelOperationResponse {
    TunnelOperationResponse {
        state: "unsupported".to_string(),
        duration_millis: 0,
        error_code: Some("android_tunnel_unavailable".to_string()),
    }
}
