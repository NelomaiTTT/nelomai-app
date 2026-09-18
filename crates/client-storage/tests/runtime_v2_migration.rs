use nelomai_client_storage::{
    ProtectedRecordStore, ProtectedRuntimeStore, RuntimePaths, RuntimeStateStore, RuntimeStateV1,
    StorageError, StoredAuth, StoredPendingCompensationStop, StoredPendingStart,
    StoredSplitTunnelState,
};
use nelomai_contracts::{ProbeFailureCode, RuntimeSlot};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Raw(Arc<Mutex<Option<Vec<u8>>>>);

impl ProtectedRecordStore for Raw {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }

    fn delete_record(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

fn recovery_v2_legacy_auth() -> StoredAuth {
    serde_json::from_value(json!({
        "install_secret": "synthetic-install-secret",
        "access_token": null,
        "refresh_token": null,
        "pending_start": {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "layer": "tic",
            "tic_connection_mode": "dynamic",
            "route_mode": "standalone",
            "egress_mode": "ipv4",
            "allow_alternate": false,
            "probes": [
                {
                    "candidate_id": "primary-candidate",
                    "latency_ms": 17.25,
                    "measured_at": "2026-09-19T10:11:12Z"
                },
                {
                    "candidate_id": "reserve-candidate",
                    "failure_code": "timeout",
                    "measured_at": "2026-09-19T10:11:13Z"
                }
            ],
            "recovery_contract_version": 2,
            "redundancy_contract_version": 1,
            "reserve_enabled": true,
            "request_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cancel_operation_id": "22222222-2222-4222-8222-222222222222"
        },
        "pending_compensation_stop": {
            "operation_id": "33333333-3333-4333-8333-333333333333",
            "lease_id": "44444444-4444-4444-8444-444444444444",
            "recovery_contract_version": 2,
            "redundant_session_id": "55555555-5555-4555-8555-555555555555",
            "accept_warm": true,
            "failure_code": "recovery_v2_cleanup"
        }
    }))
    .unwrap()
}

fn assert_recovery_v2_fields(
    pending_start: Option<&StoredPendingStart>,
    pending_compensation_stop: Option<&StoredPendingCompensationStop>,
) {
    let pending_start = pending_start.expect("pending_start must survive migration");
    assert_eq!(
        pending_start.operation_id,
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(pending_start.recovery_contract_version, Some(2));
    assert_eq!(pending_start.redundancy_contract_version, Some(1));
    assert_eq!(pending_start.reserve_enabled, Some(true));
    assert_eq!(
        pending_start.request_fingerprint.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(
        pending_start.cancel_operation_id.as_deref(),
        Some("22222222-2222-4222-8222-222222222222")
    );
    assert_eq!(pending_start.probes.len(), 2);
    assert_eq!(pending_start.probes[0].candidate_id, "primary-candidate");
    assert_eq!(pending_start.probes[0].latency_ms, Some(17.25));
    assert_eq!(pending_start.probes[0].failure_code, None);
    assert_eq!(pending_start.probes[0].measured_at, "2026-09-19T10:11:12Z");
    assert_eq!(pending_start.probes[1].candidate_id, "reserve-candidate");
    assert_eq!(pending_start.probes[1].latency_ms, None);
    assert_eq!(
        pending_start.probes[1].failure_code,
        Some(ProbeFailureCode::Timeout)
    );
    assert_eq!(pending_start.probes[1].measured_at, "2026-09-19T10:11:13Z");

    let pending_compensation_stop =
        pending_compensation_stop.expect("pending_compensation_stop must survive migration");
    assert_eq!(
        pending_compensation_stop.operation_id,
        "33333333-3333-4333-8333-333333333333"
    );
    assert_eq!(
        pending_compensation_stop.lease_id,
        "44444444-4444-4444-8444-444444444444"
    );
    assert_eq!(pending_compensation_stop.recovery_contract_version, Some(2));
    assert_eq!(
        pending_compensation_stop.redundant_session_id.as_deref(),
        Some("55555555-5555-4555-8555-555555555555")
    );
    assert!(pending_compensation_stop.accept_warm);
    assert_eq!(
        pending_compensation_stop.failure_code.as_deref(),
        Some("recovery_v2_cleanup")
    );
}

fn assert_runtime_recovery_v2_fields(state: &RuntimeStateV1) {
    assert!(state.cleanup_only);
    assert_recovery_v2_fields(
        state.pending_start.as_ref(),
        state.pending_compensation_stop.as_ref(),
    );
}

#[test]
fn recovery_v2_fields_survive_import_legacy_and_runtime_serde_roundtrip() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.3.0").unwrap();
    let legacy = recovery_v2_legacy_auth();
    assert_recovery_v2_fields(
        legacy.pending_start.as_ref(),
        legacy.pending_compensation_stop.as_ref(),
    );

    let imported =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), &paths);
    assert_runtime_recovery_v2_fields(&imported);

    let serde_roundtrip: RuntimeStateV1 =
        serde_json::from_slice(&serde_json::to_vec(&imported).unwrap()).unwrap();
    assert_eq!(serde_roundtrip, imported);
    assert_runtime_recovery_v2_fields(&serde_roundtrip);
}

#[test]
fn protected_runtime_roundtrip_preserves_recovery_v2_fields_and_exact_namespace() {
    let root = tempfile::tempdir().unwrap();
    let raw = Raw::default();
    let latest_paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.3.0").unwrap();
    let latest = ProtectedRuntimeStore::new(raw.clone(), latest_paths.clone());
    let legacy = recovery_v2_legacy_auth();
    let imported =
        RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), &latest_paths);
    assert_runtime_recovery_v2_fields(&imported);

    latest.save(&imported).unwrap();
    let loaded = latest.load().unwrap().unwrap();
    assert_eq!(loaded, imported);
    assert_runtime_recovery_v2_fields(&loaded);

    let stable = ProtectedRuntimeStore::new(
        raw,
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.20").unwrap(),
    );
    assert!(stable.load().is_err());
    assert_eq!(latest.load().unwrap(), Some(imported));
}
