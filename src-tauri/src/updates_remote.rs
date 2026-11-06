//! Product runtime facade. Capability is supplied only by authenticated native
//! admission; never probe an older strict private channel with new commands.
use nelomai_client_container::{
    host::{
        HostRequestV1, HostResponseV1, HostUpdateStatusV1, UpdateCheckReason, UpdateRequestV2,
        UpdateStatusV2,
    },
    ipc::PrivateRuntimeAuthClient,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusResponse {
    #[serde(flatten)]
    pub status: HostUpdateStatusV1,
    pub protocol: u32,
    pub offer_id: Option<String>,
    pub prompt_pending: bool,
    pub update_available: bool,
}
impl std::ops::Deref for UpdateStatusResponse {
    type Target = HostUpdateStatusV1;
    fn deref(&self) -> &Self::Target {
        &self.status
    }
}
impl From<UpdateStatusV2> for UpdateStatusResponse {
    fn from(value: UpdateStatusV2) -> Self {
        let mut status = value.status;
        status.phase = value.phase;
        Self {
            status,
            protocol: 2,
            offer_id: value.offer_id,
            prompt_pending: value.prompt_pending,
            update_available: value.update_available,
        }
    }
}
pub struct NativeUpdater {
    owner: Arc<PrivateRuntimeAuthClient>,
    protocol: u32,
    #[cfg(desktop)]
    desktop_visibility: tokio::sync::Mutex<Option<bool>>,
}
fn request_for_protocol(protocol: u32, request: UpdateRequestV2) -> Result<HostRequestV1, String> {
    if protocol == 2 {
        Ok(HostRequestV1::UpdateV2 { request })
    } else if matches!(request, UpdateRequestV2::Status {}) {
        Ok(HostRequestV1::UpdateStatus)
    } else {
        Err("update_protocol_unsupported".into())
    }
}
impl NativeUpdater {
    pub fn new(owner: Arc<PrivateRuntimeAuthClient>) -> Self {
        Self {
            owner,
            protocol: 1,
            #[cfg(desktop)]
            desktop_visibility: tokio::sync::Mutex::new(None),
        }
    }
    pub fn with_update_protocol(mut self, protocol: u32) -> Self {
        self.protocol = if protocol == 2 { 2 } else { 1 };
        self
    }
    #[cfg(desktop)]
    pub async fn report_desktop_visibility(&self, foreground: bool) -> Result<(), String> {
        if self.protocol != 2 {
            return Ok(());
        }
        let mut reported = self.desktop_visibility.lock().await;
        if *reported == Some(foreground) {
            return Ok(());
        }
        self.request(UpdateRequestV2::UiLifecycle {
            foreground,
            new_user_launch: false,
            launch_session_id: None,
        })
        .await?;
        *reported = Some(foreground);
        Ok(())
    }
    pub async fn status(&self) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::Status {}).await
    }
    pub async fn refresh(&self) -> Result<UpdateStatusResponse, String> {
        self.check(UpdateCheckReason::Startup).await
    }
    pub async fn check(&self, reason: UpdateCheckReason) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::Check { reason }).await
    }
    pub async fn set_automatic(&self, enabled: bool) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::SetAutomatic { enabled })
            .await
    }
    pub async fn confirm(&self, offer_id: String) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::Confirm { offer_id }).await
    }
    pub async fn defer(&self, offer_id: String) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::Defer { offer_id }).await
    }
    pub async fn presented(&self, offer_id: String) -> Result<UpdateStatusResponse, String> {
        self.request(UpdateRequestV2::Presented { offer_id }).await
    }
    pub async fn install(&self) -> Result<UpdateStatusResponse, String> {
        Err("update_consent_required".into())
    }
    async fn request(&self, request: UpdateRequestV2) -> Result<UpdateStatusResponse, String> {
        let request = request_for_protocol(self.protocol, request)?;
        match self
            .owner
            .owner_request(request)
            .await
            .map_err(|_| "common updater unavailable".to_string())?
        {
            HostResponseV1::UpdateV2 { status } if self.protocol == 2 => Ok(status.into()),
            HostResponseV1::UpdateStatus { mut status } if self.protocol != 2 => {
                status.supported = false;
                Ok(UpdateStatusResponse {
                    status,
                    protocol: 1,
                    offer_id: None,
                    prompt_pending: false,
                    update_available: false,
                })
            }
            _ => Err("invalid common updater response".into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nelomai_client_container::host::UpdateRequestV2;
    #[test]
    fn only_admitted_protocol_two_can_send_consent_actions() {
        for protocol in [0, 1, 3, u32::MAX] {
            assert!(request_for_protocol(
                protocol,
                UpdateRequestV2::Confirm {
                    offer_id: "offer".into()
                }
            )
            .is_err());
            assert!(matches!(
                request_for_protocol(protocol, UpdateRequestV2::Status {}).unwrap(),
                HostRequestV1::UpdateStatus
            ));
        }
        assert!(matches!(
            request_for_protocol(
                2,
                UpdateRequestV2::Confirm {
                    offer_id: "offer".into()
                }
            )
            .unwrap(),
            HostRequestV1::UpdateV2 { .. }
        ));
    }
    struct NoScope;
    impl nelomai_client_container::ipc::ScopeAdmission for NoScope {
        fn check_scope(
            &self,
            _: &nelomai_client_storage::RuntimeAuthScope,
        ) -> Result<(), nelomai_client_container::ipc::PrivateError> {
            Err(nelomai_client_container::ipc::PrivateError::Protocol)
        }
        fn bind_empty_scope(
            &self,
            _: &nelomai_client_storage::RuntimeAuthScope,
            _: &nelomai_client_core::RuntimeWriterQuiescence,
        ) -> Result<(), nelomai_client_container::ipc::PrivateError> {
            Err(nelomai_client_container::ipc::PrivateError::Protocol)
        }
    }
    struct NoStop;
    #[async_trait::async_trait]
    impl nelomai_client_container::LocalAuthStop for NoStop {
        async fn stop_local(&self) -> Result<(), nelomai_client_container::BrokerError> {
            Ok(())
        }
    }
    fn wire_updater(protocol: u32) -> (Arc<NativeUpdater>, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(8192);
        let child = Arc::new(nelomai_client_container::ipc::ChildAdmission::new(
            "updater-wire-test".into(),
            Arc::new(nelomai_client_core::RuntimeWriterGates::default()),
            Arc::new(NoScope),
        ));
        let owner = Arc::new(PrivateRuntimeAuthClient::new(
            client,
            child,
            Arc::new(NoStop),
        ));
        (
            Arc::new(NativeUpdater::new(owner).with_update_protocol(protocol)),
            peer,
        )
    }
    #[tokio::test]
    async fn bootstrap_refresh_uses_startup_while_explicit_check_stays_manual() {
        use nelomai_client_container::ipc::{
            read_frame, write_frame, AuthRequestV1, AuthResponseV1, FrameV1, MessageV1,
            PrivateError,
        };
        for startup in [true, false] {
            let (updater, mut peer) = wire_updater(2);
            let task = tokio::spawn(async move {
                if startup {
                    updater.refresh().await
                } else {
                    updater.check(UpdateCheckReason::Manual).await
                }
            });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            let frame = read_frame(&mut peer, deadline).await.unwrap();
            let reason = match frame.message {
                MessageV1::Request(AuthRequestV1::Owner {
                    request:
                        HostRequestV1::UpdateV2 {
                            request: UpdateRequestV2::Check { reason },
                        },
                }) => reason,
                _ => panic!("not an updater check"),
            };
            write_frame(
                &mut peer,
                FrameV1::new(
                    frame.id,
                    MessageV1::Response(AuthResponseV1::Error {
                        error: PrivateError::Cancelled,
                    }),
                ),
                deadline,
            )
            .await
            .unwrap();
            assert!(task.await.unwrap().is_err());
            assert_eq!(
                reason,
                if startup {
                    UpdateCheckReason::Startup
                } else {
                    UpdateCheckReason::Manual
                }
            );
        }
    }
    #[cfg(desktop)]
    #[tokio::test]
    async fn native_visibility_is_capability_gated_coalesced_and_retries_failed_ack() {
        use nelomai_client_container::ipc::{
            read_frame, write_frame, AuthRequestV1, AuthResponseV1, FrameV1, MessageV1,
            PrivateError,
        };
        let (old, mut peer) = wire_updater(1);
        old.report_desktop_visibility(false).await.unwrap();
        assert!(read_frame(
            &mut peer,
            tokio::time::Instant::now() + std::time::Duration::from_millis(20)
        )
        .await
        .is_err());
        let (owner, mut peer) = wire_updater(2);
        for (foreground, fail) in [(true, true), (true, false), (false, false)] {
            let runtime = owner.clone();
            let task =
                tokio::spawn(async move { runtime.report_desktop_visibility(foreground).await });
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
            let frame = read_frame(&mut peer, deadline).await.unwrap();
            assert!(
                matches!(frame.message,MessageV1::Request(AuthRequestV1::Owner {request:HostRequestV1::UpdateV2 {request:UpdateRequestV2::UiLifecycle {foreground:actual,new_user_launch:false,launch_session_id:None}}}) if actual==foreground)
            );
            let response = if fail {
                AuthResponseV1::Error {
                    error: PrivateError::Cancelled,
                }
            } else {
                AuthResponseV1::Owner {
                    response: HostResponseV1::UpdateV2 {
                        status: UpdateStatusV2 {
                            status: HostUpdateStatusV1 {
                                supported: true,
                                automatic: true,
                                phase: "idle".into(),
                                version: None,
                                notes: None,
                                required: false,
                                downloaded: 0,
                                total: None,
                                error_code: None,
                            },
                            phase: "idle".into(),
                            offer_id: None,
                            prompt_pending: false,
                            update_available: false,
                        },
                    },
                }
            };
            write_frame(
                &mut peer,
                FrameV1::new(frame.id, MessageV1::Response(response)),
                deadline,
            )
            .await
            .unwrap();
            assert_eq!(task.await.unwrap().is_err(), fail);
            if !fail {
                owner.report_desktop_visibility(foreground).await.unwrap();
                assert!(read_frame(
                    &mut peer,
                    tokio::time::Instant::now() + std::time::Duration::from_millis(20)
                )
                .await
                .is_err());
            }
        }
    }
}
