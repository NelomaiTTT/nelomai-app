use nelomai_client_container::{
    host::{HostRequestV1, HostResponseV1},
    ipc::PrivateRuntimeAuthClient,
    RuntimeSwitchStatusV1,
};
use nelomai_contracts::RuntimeSlot;
use std::sync::Arc;

/// All product runtimes use the same typed common-owner selection authority.
pub struct RuntimeControls(
    Arc<PrivateRuntimeAuthClient>,
    Option<nelomai_contracts::RuntimeIdentity>,
);
impl RuntimeControls {
    pub fn new(
        owner: Arc<PrivateRuntimeAuthClient>,
        target: &nelomai_client_api::RuntimeTarget,
    ) -> Self {
        Self(owner, target.identity(None).ok())
    }
    /// Frozen verified launch target; selecting another slot cannot retarget
    /// the running process. Optional diagnostics never request owner IPC.
    pub(crate) fn diagnostic_snapshot(&self) -> Option<nelomai_contracts::RuntimeIdentity> {
        self.1.clone()
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
    pub async fn prepare_restart(&self) -> Result<RuntimeSwitchStatusV1, ()> {
        self.request_owner(HostRequestV1::RuntimeRestart).await
    }
    async fn request_owner(&self, request: HostRequestV1) -> Result<RuntimeSwitchStatusV1, ()> {
        match self.0.owner_request(request).await.map_err(|_| ())? {
            HostResponseV1::RuntimeStatus { status } => Ok(status),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use nelomai_client_container::{
        ipc::{ChildAdmission, PrivateError, ScopeAdmission},
        BrokerError, LocalAuthStop,
    };
    use nelomai_client_core::{RuntimeAuthProvider, RuntimeWriterGates, RuntimeWriterQuiescence};
    use nelomai_client_storage::RuntimeAuthScope;

    struct ClosedScope;
    impl ScopeAdmission for ClosedScope {
        fn check_scope(&self, _: &RuntimeAuthScope) -> Result<(), PrivateError> {
            Err(PrivateError::RecoveryRequired)
        }
        fn bind_empty_scope(
            &self,
            _: &RuntimeAuthScope,
            _: &RuntimeWriterQuiescence,
        ) -> Result<(), PrivateError> {
            Err(PrivateError::RecoveryRequired)
        }
    }
    struct Stop;
    #[async_trait::async_trait]
    impl LocalAuthStop for Stop {
        async fn stop_local(&self) -> Result<(), BrokerError> {
            Ok(())
        }
    }
    pub(crate) fn private_peer() -> (Arc<PrivateRuntimeAuthClient>, tokio::io::DuplexStream) {
        let (socket, peer) = tokio::io::duplex(65536);
        let child = Arc::new(ChildAdmission::new(
            "test-incarnation".into(),
            Arc::new(RuntimeWriterGates::default()),
            Arc::new(ClosedScope),
        ));
        (
            Arc::new(PrivateRuntimeAuthClient::new(socket, child, Arc::new(Stop))),
            peer,
        )
    }
    fn target() -> nelomai_client_api::RuntimeTarget {
        nelomai_client_api::RuntimeTarget {
            container_version: "0.4.0".into(),
            runtime_version: "0.3.8".into(),
            runtime_slot: RuntimeSlot::Stable,
            runtime_contract_version: 2,
        }
    }
    #[tokio::test]
    async fn diagnostic_snapshot_never_queries_an_unresponsive_owner() {
        use tokio::io::AsyncReadExt;
        let (owner, mut peer) = private_peer();
        let controls = RuntimeControls::new(owner.clone(), &target());
        let snapshot = tokio::time::timeout(std::time::Duration::from_millis(50), async {
            controls.diagnostic_snapshot()
        })
        .await
        .expect("optional diagnostics must not await owner IPC")
        .unwrap();
        assert_eq!(snapshot, target().identity(None).unwrap());
        assert!(!owner.is_channel_closed());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), peer.read_u8())
                .await
                .is_err(),
            "snapshot must send no IPC request"
        );
        let mut invalid = target();
        invalid.runtime_version.clear();
        assert!(RuntimeControls::new(owner, &invalid)
            .diagnostic_snapshot()
            .is_none());
    }
}
