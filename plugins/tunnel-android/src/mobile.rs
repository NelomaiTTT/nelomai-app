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

    pub fn clear_quick_plan(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("clearQuickPlan", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn update_quick_dns(&self, request: DnsServersRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("updateQuickDns", request)
            .map_err(Into::into)
    }

    pub async fn queue_start_failure_diagnostics_async(
        &self,
        request: StartFailureDiagnosticsRequest,
    ) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async::<()>("queueStartFailureDiagnostics", request)
            .await
            .map_err(Into::into)
    }

    pub async fn update_quick_dns_async(&self, request: DnsServersRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin_async::<()>("updateQuickDns", request)
            .await
            .map_err(Into::into)
    }

    pub fn configure_background(&self, request: BackgroundCredentialRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("configureBackground", request)
            .map_err(Into::into)
    }

    pub fn rotate_background(
        &self,
        request: BackgroundCredentialMutationRequest,
    ) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("rotateBackground", request)
            .map_err(Into::into)
    }

    pub fn provision_background(&self, request: BackgroundUiProvisionRequest) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("provisionBackground", request)
            .map_err(Into::into)
    }

    pub fn background_credential_status(
        &self,
    ) -> crate::Result<BackgroundCredentialStatusResponse> {
        self.0
            .run_mobile_plugin("backgroundCredentialStatus", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn begin_connection_intent(
        &self,
        request: BeginConnectionIntentRequest,
    ) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin("beginConnectionIntent", request)
            .map_err(Into::into)
    }

    pub async fn begin_connection_intent_async(
        &self,
        request: BeginConnectionIntentRequest,
    ) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin_async("beginConnectionIntent", request)
            .await
            .map_err(Into::into)
    }

    pub fn toggle_connection_intent(&self) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin("toggleConnectionIntent", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn cancel_connection_intent(
        &self,
        request: CancelConnectionIntentRequest,
    ) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin("cancelConnectionIntent", request)
            .map_err(Into::into)
    }

    pub fn cancel_current_connection_intent(
        &self,
    ) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin("cancelCurrentConnectionIntent", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn connection_intent_status(&self) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin("connectionIntentStatus", EmptyRequest {})
            .map_err(Into::into)
    }

    pub async fn release_redundant_standby(&self) -> crate::Result<ConnectionIntentStatusResponse> {
        self.0
            .run_mobile_plugin_async("releaseRedundantStandby", EmptyRequest {})
            .await
            .map_err(Into::into)
    }

    pub fn clear_background(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>("clearBackground", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn begin_background_logout(&self) -> crate::Result<BackgroundLogoutOwnershipResponse> {
        self.0
            .run_mobile_plugin("beginBackgroundLogout", EmptyRequest {})
            .map_err(Into::into)
    }

    pub async fn recover_background_session(
        &self,
        request: BackgroundSessionRecoveryRequest,
    ) -> crate::Result<BackgroundSessionRecoveryResponse> {
        self.0
            .run_mobile_plugin_async("recoverBackgroundSession", request)
            .await
            .map_err(Into::into)
    }

    pub fn take_quick_state_change(&self) -> crate::Result<QuickStateChangeResponse> {
        self.0
            .run_mobile_plugin::<QuickStateChangeResponse>("takeQuickStateChange", EmptyRequest {})
            .map_err(Into::into)
    }

    pub fn acknowledge_quick_state_change(&self, revision: u64) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<()>(
                "acknowledgeQuickStateChange",
                QuickStateChangeAcknowledgeRequest { revision },
            )
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

    pub async fn tunnel_status_async(&self) -> crate::Result<TunnelOperationResponse> {
        self.0
            .run_mobile_plugin_async(
                "tunnelStatus",
                TunnelStatusRequest {
                    api_version: TUNNEL_API_VERSION,
                },
            )
            .await
            .map_err(Into::into)
    }

    pub async fn tunnel_metrics_async(&self, probe: bool) -> crate::Result<TunnelMetricsResponse> {
        self.0
            .run_mobile_plugin_async(
                "tunnelMetrics",
                TunnelMetricsRequest {
                    api_version: TUNNEL_API_VERSION,
                    probe,
                },
            )
            .await
            .map_err(Into::into)
    }

    pub async fn tunnel_rebind_udp_async(&self) -> crate::Result<TunnelOperationResponse> {
        self.0
            .run_mobile_plugin_async(
                "tunnelRebindUdp",
                TunnelStatusRequest {
                    api_version: TUNNEL_API_VERSION,
                },
            )
            .await
            .map_err(Into::into)
    }
}
