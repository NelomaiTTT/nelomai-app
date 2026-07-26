use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::TunnelAndroidExt;

#[command]
pub(crate) async fn probe<R: Runtime>(app: AppHandle<R>) -> Result<ProbeResponse> {
    app.tunnel_android().probe()
}

#[command]
pub(crate) async fn request_vpn_permission<R: Runtime>(
    app: AppHandle<R>,
) -> Result<PermissionResponse> {
    app.tunnel_android().request_vpn_permission()
}

#[command]
pub(crate) async fn tunnel_status<R: Runtime>(
    app: AppHandle<R>,
) -> Result<TunnelOperationResponse> {
    app.tunnel_android().tunnel_status()
}
