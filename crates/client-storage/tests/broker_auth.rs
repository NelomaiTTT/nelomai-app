use nelomai_client_storage::*;

#[test]
fn malformed_protected_broker_metadata_fails_closed_without_new_install() {
    let legacy: StoredAuth =
        serde_json::from_str(r#"{"install_secret":"synthetic-install"}"#).unwrap();
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    auth.broker = Some(BrokerMetadataV1 {
        family: String::new(),
        next_attempt: 0,
        pending_request: None,
        pending_logout: None,
        completed_resume: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: None,
    });
    assert!(auth.validate().is_err());
    assert_eq!(auth.install_secret, "synthetic-install");
}

#[test]
fn logout_proof_is_protected_payload_not_debug_output() {
    let proof = PendingLogoutV1 {
        operation_id: "op".into(),
        refresh_proof: "synthetic-proof".into(),
    };
    assert!(serde_json::to_string(&proof)
        .unwrap()
        .contains("synthetic-proof"));
    assert!(!format!("{proof:?}").contains("synthetic-proof"));
}
