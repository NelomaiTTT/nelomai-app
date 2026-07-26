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
pub(crate) async fn start_smoke_tunnel<R: Runtime>(app: AppHandle<R>) -> Result<SmokeResponse> {
    app.tunnel_android().start_smoke_tunnel()
}

#[command]
pub(crate) async fn stop_smoke_tunnel<R: Runtime>(app: AppHandle<R>) -> Result<SmokeResponse> {
    app.tunnel_android().stop_smoke_tunnel()
}

#[command]
pub(crate) async fn smoke_tunnel_status<R: Runtime>(app: AppHandle<R>) -> Result<SmokeResponse> {
    app.tunnel_android().smoke_tunnel_status()
}
