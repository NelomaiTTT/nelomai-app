use nelomai_client_container::RuntimeSwitchStatusV1;
use nelomai_contracts::RuntimeSlot;
use std::sync::Arc;
#[cfg(not(target_os = "android"))]
type Owner = nelomai_client_container::SwitchCoordinator;
#[cfg(target_os = "android")]
type Owner = nelomai_client_container::ipc::PrivateRuntimeAuthClient;

pub struct RuntimeControls(Arc<Owner>);
impl RuntimeControls {
    pub fn new(owner: Arc<Owner>) -> Self {
        Self(owner)
    }
    pub async fn status(&self) -> Result<RuntimeSwitchStatusV1, ()> {
        #[cfg(not(target_os = "android"))]
        {
            self.0.status().map_err(|_| ())
        }
        #[cfg(target_os = "android")]
        {
            self.request_owner(nelomai_client_container::host::HostRequestV1::RuntimeStatus)
                .await
        }
    }
    pub async fn request(&self, slot: RuntimeSlot) -> Result<(), ()> {
        #[cfg(not(target_os = "android"))]
        {
            self.0.request(slot).await.map(|_| ()).map_err(|_| ())
        }
        #[cfg(target_os = "android")]
        {
            self.request_owner(
                nelomai_client_container::host::HostRequestV1::RuntimeSelect { slot },
            )
            .await
            .map(|_| ())
        }
    }
    pub async fn cancel_pending(&self) -> Result<(), ()> {
        #[cfg(not(target_os = "android"))]
        {
            self.0.cancel_pending().await.map(|_| ()).map_err(|_| ())
        }
        #[cfg(target_os = "android")]
        {
            self.request_owner(nelomai_client_container::host::HostRequestV1::RuntimeCancel)
                .await
                .map(|_| ())
        }
    }
    #[cfg(target_os = "android")]
    async fn request_owner(
        &self,
        request: nelomai_client_container::host::HostRequestV1,
    ) -> Result<RuntimeSwitchStatusV1, ()> {
        match self.0.owner_request(request).await.map_err(|_| ())? {
            nelomai_client_container::host::HostResponseV1::RuntimeStatus { status } => Ok(status),
            _ => Err(()),
        }
    }
}
