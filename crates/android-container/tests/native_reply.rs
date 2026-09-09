use async_trait::async_trait;
use axum::{routing::post, Json, Router};
use nelomai_android_container::native_reply::decode_background_reply;
use nelomai_client_api::{ClientApi, RuntimeTarget};
use nelomai_client_container::{
    AuthBroker, BrokerError, LocalAuthStop, NativeAuthFailure, OwnerRuntimeAuth,
    RuntimeCacheAdmission, RuntimeClientProfile,
};
use nelomai_client_core::{CoreError, RuntimeWriterGates};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, ProtectedAuthStore, ProtectedRecordStore,
    ProtectedRuntimeStore, RuntimePaths, RuntimeRecordOwner, RuntimeStateStore, RuntimeStateV1,
    StorageError, StoredAuth, StoredSplitTunnelState,
};
use nelomai_contracts::{Platform, RuntimeIdentity, RuntimeSlot};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn refusal(code: &str) -> Result<Option<String>, ()> {
    Ok(Some(
        json!({"format":1,"outcome":"failure","code":code}).to_string(),
    ))
}

#[test]
fn exact_native_refusal_codes_keep_their_issuance_category() {
    for code in [
        "invalid_background_token",
        "invalid_background_recovery",
        "activation_not_applied",
        "background_recovery_unsupported",
        "background_owner_scope_mismatch",
        "background_credential_unavailable",
    ] {
        assert!(
            matches!(
                decode_background_reply(refusal(code)),
                Err(NativeAuthFailure::NotIssued)
            ),
            "{code}"
        );
    }
    assert!(matches!(
        decode_background_reply(refusal("app_access_unavailable")),
        Err(NativeAuthFailure::AccessUnavailable)
    ));
    for value in [
        refusal("transport_timeout"),
        refusal("exception: invalid_background_token"),
        Err(()),
        Ok(None),
        Ok(Some("not JSON".into())),
        Ok(Some("x".repeat(65537))),
    ] {
        assert!(matches!(
            decode_background_reply(value),
            Err(NativeAuthFailure::OutcomeUnknown)
        ));
    }
    assert!(matches!(
        decode_background_reply(Ok(Some(
            r#"{"format":1,"outcome":"success","value":null}"#.into()
        ))),
        Ok(None)
    ));
}

#[derive(Clone, Default)]
struct Record(Arc<Mutex<Option<Vec<u8>>>>);
impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, value: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(value.to_vec());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
struct Stop;
#[async_trait]
impl LocalAuthStop for Stop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        Ok(())
    }
}

#[tokio::test]
async fn actual_reply_adapter_clears_only_known_refusal_ticket_and_permits_refresh_fallback() {
    for (code, unknown, access_expired) in [
        ("invalid_background_token", false, false),
        ("background_credential_unavailable", false, false),
        ("background_recovery_not_issued", false, false),
        ("app_access_unavailable", false, true),
        ("native_outcome_unknown", true, false),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let router = Router::new().route("/api/client/v1/auth/refresh", post(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Json(json!({"api_version":"1","request_id":"synthetic","token_type":"Bearer",
                    "access_token":"successor-access","access_expires_in":900,"refresh_token":"successor-refresh","refresh_expires_in":3600,
                    "access":{"state":"active","can_login":true,"can_connect":true,"expires_at":null},
                    "device":{"id":"device","name":"test","platform":"android","container_version":"0.2.16","runtime_version":"0.2.16","runtime_contract_version":1,"runtime_slot":"latest","session_generation":7}}))
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = ClientApi::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let identity = RuntimeIdentity {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: Some(7),
        };
        let store = Arc::new(ProtectedAuthStore::new(Record::default()));
        let mut legacy = StoredAuth::new_install();
        legacy.install_secret = "synthetic-install".into();
        legacy.access_token = Some("initial-access".into());
        legacy.refresh_token = Some("initial-refresh".into());
        let mut auth = AuthStoreV1::from_legacy(&legacy);
        auth.session_generation = Some(7);
        auth.confirmed_identity = Some(identity.clone());
        auth.broker = Some(BrokerMetadataV1 {
            family: "synthetic-family".into(),
            next_attempt: 0,
            pending_request: None,
            completed_resume: None,
            pending_logout: None,
            pending_recovery: None,
            cancelled_login: None,
            authentication_outcome_unknown: false,
            pending_login_account: None,
            confirmed_device_id: Some("device".into()),
            pending_push_cleanup_epoch: None,
            transition_authorities: vec![],
        });
        store.save(&auth).unwrap();
        let broker = Arc::new(AuthBroker::new(api, store.clone(), Arc::new(Stop)).unwrap());
        let root = tempfile::tempdir().unwrap();
        let runtime = ProtectedRuntimeStore::new(
            Record::default(),
            RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap(),
        );
        let mut empty = RuntimeStateV1::import_legacy(
            &StoredAuth::new_install(),
            StoredSplitTunnelState::default(),
            runtime.paths(),
        );
        empty.cleanup_only = false;
        runtime.save(&empty).unwrap();
        let port = OwnerRuntimeAuth::new(
            broker.clone(),
            RuntimeTarget::from_identity(&identity),
            RuntimeClientProfile {
                platform: Platform::Android,
                platform_version: None,
                architecture: "aarch64".into(),
            },
            Arc::new(RuntimeCacheAdmission::new(RuntimeRecordOwner::new(runtime))),
            Arc::new(RuntimeWriterGates::default()),
        )
        .unwrap();
        port.admit_empty_current().await.unwrap();
        let stale = broker.access_token(None).await.unwrap();
        let dispatch_store = store.clone();
        let result = port
            .recover_background(|request| async move {
                assert_eq!(
                    dispatch_store
                        .load()
                        .unwrap()
                        .unwrap()
                        .broker
                        .unwrap()
                        .pending_recovery,
                    Some(request.ticket)
                );
                decode_background_reply(refusal(code))
                    .and_then(|value| value.ok_or(NativeAuthFailure::OutcomeUnknown))
            })
            .await;
        assert!(result.is_err());
        assert_eq!(
            matches!(result, Err(CoreError::AccessExpired)),
            access_expired,
            "{code}"
        );
        assert_eq!(
            store
                .load()
                .unwrap()
                .unwrap()
                .broker
                .unwrap()
                .pending_recovery
                .is_some(),
            unknown,
            "{code}"
        );
        let fallback = broker.access_token(Some(&stale)).await;
        if unknown {
            assert!(matches!(fallback, Err(BrokerError::RecoveryRequired)));
        } else {
            assert_eq!(fallback.unwrap().access_token(), "successor-access");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            usize::from(!unknown),
            "{code}"
        );
        server.abort();
    }
}
