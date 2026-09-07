use nelomai_client_container::{
    host::{HostRequestV1, HostResponseV1},
    ipc::PrivateRuntimeAuthClient,
    RuntimeSwitchStatusV1,
};
use nelomai_contracts::RuntimeSlot;
use std::sync::Arc;

/// All product runtimes use the same typed common-owner selection authority.
pub struct RuntimeControls(Arc<PrivateRuntimeAuthClient>);
impl RuntimeControls {
    pub fn new(owner: Arc<PrivateRuntimeAuthClient>) -> Self {
        Self(owner)
    }
    pub async fn status(&self) -> Result<RuntimeSwitchStatusV1, ()> {
        self.request_owner(HostRequestV1::RuntimeStatus).await
    }
    pub async fn request(&self, slot: RuntimeSlot) -> Result<(), ()> {
        self.request_owner(HostRequestV1::RuntimeSelect { slot })
            .await
            .map(|_| ())
    }
    pub async fn cancel_pending(&self) -> Result<(), ()> {
        self.request_owner(HostRequestV1::RuntimeCancel)
            .await
            .map(|_| ())
    }
    async fn request_owner(&self, request: HostRequestV1) -> Result<RuntimeSwitchStatusV1, ()> {
        match self.0.owner_request(request).await.map_err(|_| ())? {
            HostResponseV1::RuntimeStatus { status } => Ok(status),
            _ => Err(()),
        }
    }
}
