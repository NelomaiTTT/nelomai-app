use nelomai_client_storage::*;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};

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
        pending_push_cleanup_epoch: None,
        transition_authorities: Vec::new(),
    });
    assert!(auth.validate().is_err());
    assert_eq!(auth.install_secret, "synthetic-install");
}

fn transition_authority() -> TransitionAuthorityV1 {
    TransitionAuthorityV1 {
        schema_version: 1,
        reconcile_operation_id: "11111111-1111-4111-8111-111111111111".into(),
        request_fingerprint: "a".repeat(64),
        source_auth_epoch: 4,
        source_family: "family-a".into(),
        source_identity: None,
        source_device_id: "device-a".into(),
        source_scope_fingerprint: "b".repeat(64),
        expected_session_generation: None,
        target_identity: RuntimeIdentity {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: None,
        },
        cleanup_contract_version: 1,
        cleanup_access_proof: "synthetic-access-proof".into(),
        resume_refresh_proof: "synthetic-refresh-proof".into(),
        legacy_refresh_completed: false,
        dispatch_state: TransitionDispatchStateV1::Captured,
        reconcile_receipt: None,
        resume_ticket: None,
        resume_evidence: None,
    }
}

#[test]
fn transition_authority_is_redacted_and_rejects_torn_or_duplicate_provenance() {
    let authority = transition_authority();
    assert!(!format!("{authority:?}").contains("synthetic-access-proof"));
    assert!(!format!("{authority:?}").contains("synthetic-refresh-proof"));

    let legacy: StoredAuth =
        serde_json::from_str(r#"{"install_secret":"synthetic-install"}"#).unwrap();
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    auth.broker = Some(BrokerMetadataV1 {
        family: "family-a".into(),
        next_attempt: 0,
        pending_request: None,
        pending_logout: None,
        completed_resume: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: Some("device-a".into()),
        pending_push_cleanup_epoch: None,
        transition_authorities: vec![authority.clone(), authority.clone()],
    });
    assert!(
        auth.validate().is_err(),
        "duplicate operation authority must fail"
    );

    auth.broker.as_mut().unwrap().transition_authorities = vec![authority];
    let mut torn = serde_json::to_value(&auth).unwrap();
    torn["broker"]["transition_authorities"][0]["dispatch_state"] =
        serde_json::json!("response_known");
    let torn: AuthStoreV1 = serde_json::from_value(torn).unwrap();
    assert!(
        torn.validate().is_err(),
        "known response requires its receipt"
    );
}

#[test]
fn transition_resume_proof_requires_exact_clean_receipt_and_full_access_evidence() {
    let legacy: StoredAuth =
        serde_json::from_str(r#"{"install_secret":"synthetic-install"}"#).unwrap();
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    let mut authority = transition_authority();
    authority.dispatch_state = TransitionDispatchStateV1::ResponseKnown;
    authority.reconcile_receipt = Some(TransitionReconcileReceiptV1 {
        state: "retry".into(),
        operation_id: authority.reconcile_operation_id.clone(),
        retired_lease_ids: Vec::new(),
        retired_session_ids: Vec::new(),
        retired_operation_ids: Vec::new(),
        retry_after_seconds: Some(1),
    });
    let ticket = BrokerRequestV1 {
        kind: BrokerRequestKind::Resume,
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        attempt: 1,
        auth_epoch: authority.source_auth_epoch,
        source_identity: None,
        source_device_id: Some(authority.source_device_id.clone()),
        prior_login_outcome_unknown: false,
        resume: Some(StoredResumeArgumentsV1 {
            reconcile_operation_id: authority.reconcile_operation_id.clone(),
            decision: "apply".into(),
            target: authority.target_identity.clone(),
            expected_session_generation: None,
        }),
    };
    authority.resume_ticket = Some(ticket);
    auth.auth_epoch = authority.source_auth_epoch;
    auth.broker = Some(BrokerMetadataV1 {
        family: authority.source_family.clone(),
        next_attempt: 1,
        pending_request: None,
        pending_logout: None,
        completed_resume: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: Some(authority.source_device_id.clone()),
        pending_push_cleanup_epoch: None,
        transition_authorities: vec![authority],
    });
    assert!(
        auth.validate().is_err(),
        "retry must never authorize resume"
    );

    let authority = &mut auth.broker.as_mut().unwrap().transition_authorities[0];
    authority.reconcile_receipt.as_mut().unwrap().state = "clean".into();
    authority
        .reconcile_receipt
        .as_mut()
        .unwrap()
        .retry_after_seconds = None;
    authority.resume_evidence = Some(TransitionResumeEvidenceV1 {
        operation_id: "22222222-2222-4222-8222-222222222222".into(),
        reconcile_operation_id: authority.reconcile_operation_id.clone(),
        decision: "apply".into(),
        target_identity: authority.target_identity.clone(),
        identity: RuntimeIdentity {
            session_generation: Some(1),
            ..authority.target_identity.clone()
        },
        access_token: "synthetic-access".into(),
        token_type: "Basic".into(),
        access_expires_in: 900,
    });
    assert!(
        auth.validate().is_err(),
        "non-Bearer evidence must fail closed"
    );
    auth.broker.as_mut().unwrap().transition_authorities[0]
        .resume_evidence
        .as_mut()
        .unwrap()
        .token_type = "Bearer".into();
    assert!(auth.validate().is_ok());
}

#[test]
fn old_broker_record_defaults_to_no_transition_authority() {
    let legacy: StoredAuth =
        serde_json::from_str(r#"{"install_secret":"synthetic-install"}"#).unwrap();
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    auth.broker = Some(BrokerMetadataV1 {
        family: "family-a".into(),
        next_attempt: 0,
        pending_request: None,
        pending_logout: None,
        completed_resume: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: None,
        pending_push_cleanup_epoch: None,
        transition_authorities: Vec::new(),
    });
    let mut raw = serde_json::to_value(auth).unwrap();
    raw["broker"]
        .as_object_mut()
        .unwrap()
        .remove("transition_authorities");
    let decoded: AuthStoreV1 = serde_json::from_value(raw).unwrap();
    assert!(decoded.broker.unwrap().transition_authorities.is_empty());
}

#[test]
fn legacy_transition_tickets_reject_nonlegacy_source_provenance() {
    let legacy: StoredAuth =
        serde_json::from_str(r#"{"install_secret":"synthetic-install"}"#).unwrap();
    let mut auth = AuthStoreV1::from_legacy(&legacy);
    let identity = transition_authority().target_identity;
    auth.broker = Some(BrokerMetadataV1 {
        family: "family-a".into(),
        next_attempt: 1,
        pending_request: Some(BrokerRequestV1 {
            kind: BrokerRequestKind::LegacyRefresh,
            operation_id: "11111111-1111-4111-8111-111111111111".into(),
            attempt: 1,
            auth_epoch: 0,
            source_identity: Some(identity),
            source_device_id: None,
            prior_login_outcome_unknown: false,
            resume: None,
        }),
        pending_logout: None,
        completed_resume: None,
        pending_recovery: None,
        cancelled_login: None,
        authentication_outcome_unknown: false,
        pending_login_account: None,
        confirmed_device_id: None,
        pending_push_cleanup_epoch: None,
        transition_authorities: Vec::new(),
    });
    assert!(auth.validate().is_err());
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
