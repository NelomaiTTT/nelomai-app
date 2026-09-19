use nelomai_client_container::ipc::{ChildAdmission, PrivateError, ScopeAdmission};
use nelomai_client_core::RuntimeWriterGates;
use nelomai_client_storage::*;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};

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
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
fn scope() -> RuntimeAuthScope {
    RuntimeAuthScope {
        auth_epoch: 1,
        family: "synthetic-family".into(),
        identity: RuntimeIdentity {
            container_version: "0.2.16".into(),
            runtime_version: "0.2.16".into(),
            runtime_contract_version: 1,
            slot: RuntimeSlot::Stable,
            session_generation: Some(1),
        },
    }
}
type AdmissionFixture = (
    tempfile::TempDir,
    Arc<ChildAdmission>,
    Arc<RuntimeWriterGates>,
    Arc<RuntimeRecordOwner<ProtectedRuntimeStore<Record>>>,
);
fn fixture() -> AdmissionFixture {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let store = ProtectedRuntimeStore::new(Record::default(), paths);
    let mut initial = RuntimeStateV1::import_legacy(
        &StoredAuth::new_install(),
        StoredSplitTunnelState::default(),
        store.paths(),
    );
    initial.cleanup_only = false;
    store.save(&initial).unwrap();
    let owner = RuntimeRecordOwner::new(store);
    let writers = Arc::new(RuntimeWriterGates::default());
    let admission = Arc::new(ChildAdmission::new(
        "fixture-child".into(),
        writers.clone(),
        owner.clone() as Arc<dyn ScopeAdmission>,
    ));
    (root, admission, writers, owner)
}

#[tokio::test]
async fn commit_keeps_actual_writers_and_latch_closed_until_final_grant() {
    let (_root, child, writers, owner) = fixture();
    let lease = child
        .prepare(1, "fixture-child", Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    child.commit(&lease, &scope()).unwrap();
    assert!(child.check(&scope()).is_err());
    assert!(writers.lifecycle().try_lock().is_err());
    assert_eq!(
        owner.operational().load().unwrap().unwrap().auth_scope,
        Some(scope())
    );
    child.grant(&lease, &scope()).unwrap();
    child.check(&scope()).unwrap();
    assert!(writers.lifecycle().try_lock().is_ok());
}

#[tokio::test]
async fn revoke_cancels_held_writers_and_late_commit_without_erasing_scope() {
    let (_root, child, writers, owner) = fixture();
    let lease = child
        .prepare(1, "fixture-child", Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    child.commit(&lease, &scope()).unwrap();
    child.revoke();
    assert_eq!(child.commit(&lease, &scope()), Err(PrivateError::Cancelled));
    assert_eq!(child.grant(&lease, &scope()), Err(PrivateError::Cancelled));
    assert!(child.check(&scope()).is_err());
    assert!(writers.lifecycle().try_lock().is_ok());
    assert_eq!(
        owner.operational().load().unwrap().unwrap().auth_scope,
        Some(scope())
    );
}

#[tokio::test(start_paused = true)]
async fn held_writer_and_deadline_cannot_issue_or_orphan_child_lease() {
    let (_root, child, writers, _) = fixture();
    let gate = writers.lifecycle();
    let held = gate.lock().await;
    assert_eq!(
        child
            .prepare(1, "fixture-child", Instant::now() + Duration::from_secs(10))
            .await,
        Err(PrivateError::Timeout)
    );
    drop(held);
    let lease = child
        .prepare(2, "fixture-child", Instant::now() + Duration::from_secs(10))
        .await
        .unwrap();
    child.commit(&lease, &scope()).unwrap();
    tokio::time::sleep(Duration::from_secs(10)).await;
    child.expire();
    assert!(writers.lifecycle().try_lock().is_ok());
    assert!(child.grant(&lease, &scope()).is_err());
    assert!(child
        .prepare(
            3,
            "replacement-child",
            Instant::now() + Duration::from_secs(10)
        )
        .await
        .is_err());
}

#[tokio::test]
async fn revoke_during_writer_acquisition_rejects_late_prepare() {
    let (_root, child, writers, _) = fixture();
    let gate = writers.lifecycle();
    let held = gate.lock().await;
    let prepare = child.prepare(1, "fixture-child", Instant::now() + Duration::from_secs(10));
    tokio::pin!(prepare);
    tokio::select! { biased; _ = &mut prepare => panic!("writer must hold preparation"), _ = tokio::task::yield_now() => {} }
    child.revoke();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), prepare)
            .await
            .expect("revoke must cancel acquisition while writer remains held"),
        Err(PrivateError::Cancelled)
    );
    drop(held);
    assert!(writers.lifecycle().try_lock().is_ok());
}
