use nelomai_client_api::ClientApiError;
use nelomai_client_core::CoreApiError;

#[test]
fn unavailable_private_transport_keeps_authentication_recovery_retryable() {
    assert_eq!(
        CoreApiError::from(ClientApiError::ControlTransportUnavailable),
        CoreApiError::Retryable
    );
}
