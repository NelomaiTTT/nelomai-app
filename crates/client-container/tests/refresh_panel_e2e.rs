use async_trait::async_trait;
use nelomai_client_api::ClientApi;
use nelomai_client_container::{AuthBroker, BrokerError, LocalAuthStop};
use nelomai_client_storage::{
    AuthStore, AuthStoreV1, BrokerMetadataV1, BrokerRequestKind, BrokerRequestV1,
    ProtectedAuthStore, ProtectedRecordStore, StorageError, StoredAuth,
};
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Record(Arc<Mutex<Option<Vec<u8>>>>);
impl ProtectedRecordStore for Record {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(bytes.into());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        panic!("recovery must preserve auth")
    }
}
struct NeverStop;
#[async_trait]
impl LocalAuthStop for NeverStop {
    async fn stop_local(&self) -> Result<(), BrokerError> {
        panic!("refresh must not stop VPN")
    }
}

#[tokio::test]
#[ignore = "run using panel scripts/check-recoverable-refresh-e2e.py; synthetic loopback fixture required"]
async fn real_panel_response_loss_and_legacy_recovery_preserve_identity_without_login() {
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NELOMAI_REFRESH_TEST_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let url = fixture["url"].as_str().unwrap();
    assert!(url.starts_with("http://127.0.0.1:"));
    for case in fixture["cases"].as_array().unwrap() {
        let mut legacy = StoredAuth::new_install();
        legacy.install_secret = case["install_secret"].as_str().unwrap().into();
        legacy.access_token = Some(case["access_token"].as_str().unwrap().into());
        legacy.refresh_token = Some(case["refresh_token"].as_str().unwrap().into());
        let mut auth = AuthStoreV1::from_legacy(&legacy);
        auth.confirmed_identity = Some(RuntimeIdentity {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Latest,
            session_generation: Some(1),
        });
        auth.session_generation = Some(1);
        auth.broker = Some(BrokerMetadataV1 {
            family: "synthetic-local-family".into(),
            next_attempt: 1,
            pending_request: None,
            completed_resume: None,
            pending_logout: None,
            pending_recovery: None,
            cancelled_login: None,
            authentication_outcome_unknown: false,
            pending_login_account: None,
            confirmed_device_id: Some(case["device_id"].as_str().unwrap().into()),
            pending_push_cleanup_epoch: None,
            transition_authorities: vec![],
        });
        if case["mode"] != "ordinary" {
            auth.broker.as_mut().unwrap().pending_request = Some(BrokerRequestV1 {
                kind: BrokerRequestKind::Refresh,
                operation_id: case["operation_id"].as_str().unwrap().into(),
                attempt: 1,
                auth_epoch: auth.auth_epoch,
                source_identity: auth.confirmed_identity.clone(),
                source_device_id: auth.broker.as_ref().unwrap().confirmed_device_id.clone(),
                prior_login_outcome_unknown: false,
                resume: None,
                refresh: None,
            });
        }
        let store = Arc::new(ProtectedAuthStore::new(Record::default()));
        store.save(&auth).unwrap();
        let api = ClientApi::new(url).unwrap();
        let broker = AuthBroker::new(api.clone(), store.clone(), Arc::new(NeverStop)).unwrap();
        let first = if case["mode"] == "ordinary" {
            let old = broker.access_token(None).await.unwrap();
            broker.access_token(Some(&old)).await.map(|_| ())
        } else {
            broker.recover_pending_refresh().await
        };
        assert!(matches!(first, Err(BrokerError::RefreshPending)));
        let pending = store
            .load()
            .unwrap()
            .unwrap()
            .broker
            .unwrap()
            .pending_request
            .unwrap();
        drop(broker);
        let broker = AuthBroker::new(api, store.clone(), Arc::new(NeverStop)).unwrap();
        broker.recover_pending_refresh().await.unwrap();
        let current = broker.access_token(None).await.unwrap();
        assert_eq!(
            current.identity(),
            auth.confirmed_identity.as_ref().unwrap()
        );
        assert_eq!(current.auth_epoch(), auth.auth_epoch);
        assert_ne!(
            current.access_token(),
            case["access_token"].as_str().unwrap()
        );
        assert!(!pending.operation_id.is_empty());
        let saved = store.load().unwrap().unwrap();
        assert_eq!(
            saved.broker.as_ref().unwrap().family,
            "synthetic-local-family"
        );
        assert!(saved.broker.unwrap().pending_request.is_none());
    }
}
