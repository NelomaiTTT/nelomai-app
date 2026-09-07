//! Product runtime facade; only the common process owns preferences/installers.
pub use nelomai_client_container::host::HostUpdateStatusV1 as UpdateStatusResponse;
use nelomai_client_container::{
    host::{HostRequestV1, HostResponseV1},
    ipc::PrivateRuntimeAuthClient,
};
use std::sync::Arc;
pub struct NativeUpdater(Arc<PrivateRuntimeAuthClient>);
impl NativeUpdater {
    pub fn new(owner: Arc<PrivateRuntimeAuthClient>) -> Self {
        Self(owner)
    }
    pub async fn status(&self) -> Result<UpdateStatusResponse, String> {
        self.request(HostRequestV1::UpdateStatus).await
    }
    pub async fn refresh(&self) -> Result<UpdateStatusResponse, String> {
        self.request(HostRequestV1::UpdateRefresh).await
    }
    pub async fn set_automatic(&self, enabled: bool) -> Result<UpdateStatusResponse, String> {
        self.request(HostRequestV1::UpdateSetAutomatic { enabled })
            .await
    }
    pub async fn install(&self) -> Result<UpdateStatusResponse, String> {
        self.request(HostRequestV1::UpdateInstall).await
    }
    pub fn ready_to_restart(&self) -> bool {
        false
    }
    async fn request(&self, request: HostRequestV1) -> Result<UpdateStatusResponse, String> {
        match self
            .0
            .owner_request(request)
            .await
            .map_err(|_| "common updater unavailable".to_string())?
        {
            HostResponseV1::UpdateStatus { status } => Ok(status),
            _ => Err("invalid common updater response".into()),
        }
    }
}
