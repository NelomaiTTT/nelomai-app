use nelomai_client_api::{RecoverableRefreshRequest, RefreshModeV1};
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};

#[test]
fn request_uses_panel_identity_names_and_redacts_both_secrets() {
    let request = RecoverableRefreshRequest {
        contract_version: 1,
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        device_id: "22222222-2222-4222-8222-222222222222".into(),
        source_identity: RuntimeIdentity {
            slot: RuntimeSlot::Latest,
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            session_generation: Some(7),
        },
        mode: RefreshModeV1::RecoverLegacyPending,
        refresh_token: "synthetic-refresh-secret".into(),
        install_secret: "synthetic-install-secret".into(),
    };
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["source_identity"]["runtime_slot"], "latest");
    assert!(value["source_identity"].get("slot").is_none());
    assert_eq!(value["source_identity"]["session_generation"], 7);
    assert_eq!(value["mode"], "recover_legacy_pending");
    let debug = format!("{request:?}");
    assert!(!debug.contains(&request.refresh_token));
    assert!(!debug.contains(&request.install_secret));
}
