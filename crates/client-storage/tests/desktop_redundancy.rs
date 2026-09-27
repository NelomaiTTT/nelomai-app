use nelomai_client_storage::{
    ProtectedRecordStore, ProtectedRuntimeStore, RuntimeRecordOwner, RuntimeStateStore,
    StorageError,
};
use nelomai_client_storage::{RuntimePaths, RuntimeStateV1};
use nelomai_contracts::RuntimeSlot;
use serde_json::json;
use std::sync::Mutex;

#[derive(Default)]
struct Raw(Mutex<Option<Vec<u8>>>);
impl ProtectedRecordStore for Raw {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(bytes.into());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn desktop_session_survives_roundtrip_and_is_not_an_empty_runtime() {
    let paths = RuntimePaths::new("/synthetic", RuntimeSlot::Latest, "0.3.3").unwrap();
    let mut raw = serde_json::to_value(RuntimeStateV1::empty(&paths, false)).unwrap();
    let start: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/valid/connection-start-redundant-response.json"
    ))
    .unwrap();
    raw["desktop_redundancy"] = json!({
        "runtime_generation":7, "connection_generation":3,
        "start_operation_id":"11111111-1111-4111-8111-111111111111",
        "request_fingerprint":"f".repeat(64),
        "connection":start["connection"], "session":start["redundancy"],
        "pending_acquire":null, "candidate":null, "stop":null
    });
    let mut state: RuntimeStateV1 = serde_json::from_value(raw.clone()).unwrap();
    assert!(!state.operationally_empty());
    let cleanup = state.cleanup_snapshot();
    assert_eq!(
        cleanup.redundant_session_ids,
        vec!["20000000-0000-4000-8000-000000000001"]
    );
    assert_eq!(cleanup.lease_ids.len(), 2);
    assert_eq!(cleanup.operations.len(), 1);
    assert_eq!(cleanup.operations[0].contract_version, Some(2));
    let restored: RuntimeStateV1 =
        serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
    assert_eq!(restored, state);
    let debug = format!("{state:?}");
    assert!(!debug.contains("standby-delivered-only-to-core"));
    let backend = ProtectedRuntimeStore::new(Raw::default(), paths.clone());
    backend.save(&RuntimeStateV1::empty(&paths, false)).unwrap();
    let owner = RuntimeRecordOwner::new(backend);
    owner.operational().save(&state).unwrap();
    assert_eq!(owner.operational().load().unwrap(), Some(state.clone()));
    assert_eq!(owner.cleanup_snapshot().unwrap(), cleanup);
    state.complete_legacy_cleanup();
    assert!(state.operationally_empty());
}

#[test]
fn old_runtime_has_no_desktop_pair_and_no_synthesized_lease() {
    let paths = RuntimePaths::new("/synthetic", RuntimeSlot::Latest, "0.3.3").unwrap();
    let mut raw = serde_json::to_value(RuntimeStateV1::empty(&paths, false)).unwrap();
    raw.as_object_mut().unwrap().remove("desktop_redundancy");
    let state: RuntimeStateV1 = serde_json::from_value(raw).unwrap();
    assert!(state.operationally_empty());
    assert!(serde_json::to_value(state)
        .unwrap()
        .get("desktop_redundancy")
        .is_none());
}
