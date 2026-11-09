//! Lost completion acknowledgements must not strand an already committed update.
use nelomai_client_container::ipc::{
    ChildAdmission, RuntimeRecordInventory, ScopeAdmission, REQUEST_BUDGET,
};
use nelomai_client_core::RuntimeWriterGates;
use nelomai_client_storage::*;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use std::sync::{Arc, Mutex};
use tokio::time::Instant;

#[derive(Clone, Default)]
struct MemoryRecord {
    bytes: Arc<Mutex<Option<Vec<u8>>>>,
    fail_save: Arc<Mutex<bool>>,
}
impl ProtectedRecordStore for MemoryRecord {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bytes.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        if std::mem::take(&mut *self.fail_save.lock().unwrap()) {
            return Err(StorageError::RecoveryRequired("injected save failure"));
        }
        *self.bytes.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        *self.bytes.lock().unwrap() = None;
        Ok(())
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    source: MemoryRecord,
    target: MemoryRecord,
    source_paths: RuntimePaths,
    target_paths: RuntimePaths,
    frozen: RuntimeCleanupSnapshotV1,
    scope: RuntimeAuthScope,
}
impl Fixture {
    fn new(same_record: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source_paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.3.0").unwrap();
        let target_paths = RuntimePaths::new(
            root.path(),
            RuntimeSlot::Latest,
            if same_record { "0.3.0" } else { "0.3.2" },
        )
        .unwrap();
        let source = MemoryRecord::default();
        let target = if same_record {
            source.clone()
        } else {
            MemoryRecord::default()
        };
        let mut state = RuntimeStateV1::empty(&source_paths, false);
        state.auth_scope = Some(RuntimeAuthScope {
            auth_epoch: 0,
            family: "test-family".into(),
            identity: RuntimeIdentity {
                slot: RuntimeSlot::Latest,
                runtime_version: "0.3.0".into(),
                container_version: "0.3.0".into(),
                runtime_contract_version: 1,
                session_generation: Some(7),
            },
        });
        state.pending_compensation_stop = Some(pending("old-lease"));
        let source_store = ProtectedRuntimeStore::new(source.clone(), source_paths.clone());
        source_store.save(&state).unwrap();
        if !same_record {
            ProtectedRuntimeStore::new(target.clone(), target_paths.clone())
                .save(&RuntimeStateV1::empty(&target_paths, true))
                .unwrap();
        }
        let frozen = RuntimeRecordOwner::new(source_store)
            .cleanup_snapshot()
            .unwrap();
        let scope = RuntimeAuthScope {
            auth_epoch: 0,
            family: "test-family".into(),
            identity: RuntimeIdentity {
                slot: RuntimeSlot::Latest,
                runtime_version: target_paths.runtime_version().into(),
                container_version: "0.3.2".into(),
                runtime_contract_version: 1,
                session_generation: Some(8),
            },
        };
        Self {
            _root: root,
            source,
            target,
            source_paths,
            target_paths,
            frozen,
            scope,
        }
    }
    fn source_store(&self) -> ProtectedRuntimeStore<MemoryRecord> {
        ProtectedRuntimeStore::new(self.source.clone(), self.source_paths.clone())
    }
    fn target_store(&self) -> ProtectedRuntimeStore<MemoryRecord> {
        ProtectedRuntimeStore::new(self.target.clone(), self.target_paths.clone())
    }
    fn child(&self) -> ChildAdmission {
        let retained = if self.source_paths == self.target_paths {
            vec![]
        } else {
            vec![RuntimeRecordOwner::new(self.source_store())]
        };
        self.child_with(retained)
    }
    fn child_with(
        &self,
        retained: Vec<Arc<RuntimeRecordOwner<ProtectedRuntimeStore<MemoryRecord>>>>,
    ) -> ChildAdmission {
        ChildAdmission::new(
            "test-incarnation".into(),
            Arc::new(RuntimeWriterGates::default()),
            Arc::new(RuntimeRecordInventory::new(
                RuntimeRecordOwner::new(self.target_store()),
                retained,
            )),
        )
    }
    async fn commit_without_ack(&self) {
        let child = self.child();
        let lease = child
            .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
            .await
            .unwrap();
        child
            .complete_cleanup(&lease, &self.frozen, &self.scope)
            .unwrap();
        // Close the process-local admission state; the two records remain durable.
        child.close();
    }
    async fn assert_replay(&self) {
        let source_before = self.source.load_record().unwrap();
        let target_before = self.target.load_record().unwrap();
        let child = self.child();
        assert!(child.check(&self.scope).is_err());
        let lease = child
            .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
            .await
            .unwrap();
        child
            .complete_cleanup(&lease, &self.frozen, &self.scope)
            .unwrap();
        child.grant(&lease, &self.scope).unwrap();
        assert!(child.check(&self.scope).is_ok());
        assert_eq!(self.source.load_record().unwrap(), source_before);
        assert_eq!(self.target.load_record().unwrap(), target_before);
    }
    async fn assert_rejected(&self, child: ChildAdmission) {
        let source_before = self.source.load_record().unwrap();
        let target_before = self.target.load_record().unwrap();
        let lease = child
            .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
            .await
            .unwrap();
        assert!(child
            .complete_cleanup(&lease, &self.frozen, &self.scope)
            .is_err());
        assert!(child.grant(&lease, &self.scope).is_err());
        assert!(child.check(&self.scope).is_err());
        assert_eq!(self.source.load_record().unwrap(), source_before);
        assert_eq!(self.target.load_record().unwrap(), target_before);
    }
}
fn pending(lease: &str) -> StoredPendingCompensationStop {
    StoredPendingCompensationStop {
        operation_id: "test-operation".into(),
        lease_id: lease.into(),
        accept_warm: false,
        failure_code: None,
        recovery_contract_version: None,
        redundant_session_id: None,
    }
}

#[tokio::test]
async fn cross_version_cleanup_replays_after_lost_ack_and_restart() {
    let fixture = Fixture::new(false);
    fixture.commit_without_ack().await;
    fixture.assert_replay().await;
}

#[tokio::test]
async fn same_record_cleanup_replays_after_lost_ack_and_restart() {
    let fixture = Fixture::new(true);
    fixture.commit_without_ack().await;
    fixture.assert_replay().await;
}

#[tokio::test(start_paused = true)]
async fn cleanup_replays_when_ack_arrives_after_admission_deadline() {
    let fixture = Fixture::new(false);
    let child = fixture.child();
    let lease = child
        .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
        .await
        .unwrap();
    child
        .complete_cleanup(&lease, &fixture.frozen, &fixture.scope)
        .unwrap();
    tokio::time::advance(REQUEST_BUDGET + std::time::Duration::from_millis(1)).await;
    assert!(child.grant(&lease, &fixture.scope).is_err());
    let retry = child
        .prepare(2, "test-incarnation", Instant::now() + REQUEST_BUDGET)
        .await
        .unwrap();
    child
        .complete_cleanup(&retry, &fixture.frozen, &fixture.scope)
        .unwrap();
    child.grant(&retry, &fixture.scope).unwrap();
    assert!(child.check(&fixture.scope).is_ok());
}

#[tokio::test]
async fn cleanup_retry_finishes_source_after_target_was_saved() {
    let fixture = Fixture::new(false);
    *fixture.source.fail_save.lock().unwrap() = true;
    let child = fixture.child();
    let lease = child
        .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
        .await
        .unwrap();
    assert!(child
        .complete_cleanup(&lease, &fixture.frozen, &fixture.scope)
        .is_err());
    assert!(child.check(&fixture.scope).is_err());
    assert_eq!(
        fixture.target_store().load().unwrap().unwrap().auth_scope,
        Some(fixture.scope.clone())
    );
    assert!(fixture
        .source_store()
        .load()
        .unwrap()
        .unwrap()
        .pending_compensation_stop
        .is_some());
    child.close();
    fixture.commit_without_ack().await;
    fixture.assert_replay().await;
}

#[tokio::test]
async fn cleanup_retry_preserves_changed_or_uncertain_source() {
    for case in ["debt", "scope", "cleanup_only", "split"] {
        let fixture = Fixture::new(false);
        fixture.commit_without_ack().await;
        let mut state = fixture.source_store().load().unwrap().unwrap();
        match case {
            "debt" => state.pending_compensation_stop = Some(pending("new-lease")),
            "scope" => state.auth_scope = fixture.frozen.auth_scope.clone(),
            "cleanup_only" => state.cleanup_only = true,
            "split" => state.applied_split_tunnel.working_policy_hash = Some("changed".into()),
            _ => unreachable!(),
        }
        fixture.source_store().save(&state).unwrap();
        fixture.assert_rejected(fixture.child()).await;
    }
}

#[tokio::test]
async fn cleanup_retry_rejects_target_with_other_identity_or_new_work() {
    for same_record in [false, true] {
        for case in [
            "family",
            "epoch",
            "generation",
            "container",
            "cleanup_only",
            "debt",
            "split",
        ] {
            let fixture = Fixture::new(same_record);
            fixture.commit_without_ack().await;
            let mut state = fixture.target_store().load().unwrap().unwrap();
            match case {
                "family" => state.auth_scope.as_mut().unwrap().family = "other-family".into(),
                "epoch" => state.auth_scope.as_mut().unwrap().auth_epoch += 1,
                "generation" => {
                    state
                        .auth_scope
                        .as_mut()
                        .unwrap()
                        .identity
                        .session_generation = Some(9)
                }
                "container" => {
                    state
                        .auth_scope
                        .as_mut()
                        .unwrap()
                        .identity
                        .container_version = "0.3.3".into()
                }
                "cleanup_only" => state.cleanup_only = true,
                "debt" => state.pending_compensation_stop = Some(pending("new-lease")),
                "split" => state.applied_split_tunnel.working_policy_hash = Some("changed".into()),
                _ => unreachable!(),
            }
            fixture.target_store().save(&state).unwrap();
            fixture.assert_rejected(fixture.child()).await;
        }
    }
}

#[tokio::test]
async fn cleanup_retry_rejects_missing_corrupt_or_ambiguous_source() {
    for case in ["missing", "corrupt", "duplicate", "unavailable"] {
        let fixture = Fixture::new(false);
        fixture.commit_without_ack().await;
        let child = match case {
            "missing" => fixture.child_with(vec![]),
            "duplicate" => fixture.child_with(vec![
                RuntimeRecordOwner::new(fixture.source_store()),
                RuntimeRecordOwner::new(fixture.source_store()),
            ]),
            "corrupt" => {
                fixture.source.save_record(b"corrupt").unwrap();
                fixture.child()
            }
            "unavailable" => {
                fixture.source.delete_record().unwrap();
                fixture.child()
            }
            _ => unreachable!(),
        };
        fixture.assert_rejected(child).await;
    }
}

#[tokio::test]
async fn cleanup_replay_does_not_depend_on_unrelated_retained_records() {
    let fixture = Fixture::new(false);
    fixture.commit_without_ack().await;
    let unrelated = RuntimePaths::new(fixture._root.path(), RuntimeSlot::Stable, "0.2.20").unwrap();
    let child = fixture.child_with(vec![
        RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
            MemoryRecord::default(),
            unrelated,
        )),
        RuntimeRecordOwner::new(fixture.source_store()),
    ]);
    let lease = child
        .prepare(1, "test-incarnation", Instant::now() + REQUEST_BUDGET)
        .await
        .unwrap();
    child
        .complete_cleanup(&lease, &fixture.frozen, &fixture.scope)
        .unwrap();
    child.grant(&lease, &fixture.scope).unwrap();
    assert!(child.check(&fixture.scope).is_ok());
}

#[tokio::test]
async fn empty_unbound_target_cannot_hide_uncleared_source_scope() {
    let fixture = Fixture::new(false);
    fixture.commit_without_ack().await;
    let mut source = fixture.source_store().load().unwrap().unwrap();
    source.auth_scope = fixture.frozen.auth_scope.clone();
    fixture.source_store().save(&source).unwrap();
    fixture
        .target_store()
        .save(&RuntimeStateV1::empty(&fixture.target_paths, false))
        .unwrap();
    fixture.assert_rejected(fixture.child()).await;
}

#[tokio::test]
async fn newer_container_can_complete_old_cleanup_into_its_verified_empty_target() {
    let fixture = Fixture::new(false);
    fixture.commit_without_ack().await;
    // 0.3.2 saved the cleanup but not the journal ACK. The verified installed
    // 0.3.3 has superseded that server transition and receives generation 9.
    let paths = RuntimePaths::new(fixture._root.path(), RuntimeSlot::Latest, "0.3.3").unwrap();
    let raw = MemoryRecord::default();
    let store = ProtectedRuntimeStore::new(raw.clone(), paths.clone());
    store.save(&RuntimeStateV1::empty(&paths, true)).unwrap();
    let scope = RuntimeAuthScope {
        identity: RuntimeIdentity {
            runtime_version: "0.3.3".into(),
            container_version: "0.3.3".into(),
            session_generation: Some(9),
            ..fixture.scope.identity.clone()
        },
        ..fixture.scope.clone()
    };
    let source_before = fixture.source.load_record().unwrap();
    let previous_before = fixture.target.load_record().unwrap();
    for _ in 0..2 {
        let child = ChildAdmission::new(
            "new-install".into(),
            Arc::new(RuntimeWriterGates::default()),
            Arc::new(RuntimeRecordInventory::new(
                RuntimeRecordOwner::new(ProtectedRuntimeStore::new(raw.clone(), paths.clone())),
                vec![
                    RuntimeRecordOwner::new(fixture.source_store()),
                    RuntimeRecordOwner::new(fixture.target_store()),
                ],
            )),
        );
        let lease = child
            .prepare(1, "new-install", Instant::now() + REQUEST_BUDGET)
            .await
            .unwrap();
        child
            .complete_cleanup(&lease, &fixture.frozen, &scope)
            .unwrap();
        child.grant(&lease, &scope).unwrap();
        assert!(child.check(&scope).is_ok());
        child.close();
    }
    assert_eq!(fixture.source.load_record().unwrap(), source_before);
    assert_eq!(fixture.target.load_record().unwrap(), previous_before);
    assert_eq!(store.load().unwrap().unwrap().auth_scope, Some(scope));
}

fn logout_receipt(fixture: &Fixture) -> CompletedRuntimeLogoutV1 {
    let scope = fixture.frozen.auth_scope.as_ref().unwrap();
    CompletedRuntimeLogoutV1 {
        operation_id: "11111111-1111-4111-8111-111111111111".into(),
        source: RuntimeLogoutSourceV1 {
            auth_epoch: scope.auth_epoch,
            family: scope.family.clone(),
            identity: Some(scope.identity.clone()),
            device_id: "test-device".into(),
            scope_fingerprint: "a".repeat(64),
        },
        code: "session_revoked_cleanup_accepted".into(),
        cleanup_reconcile_operation_id: Some("22222222-2222-4222-8222-222222222222".into()),
    }
}

#[tokio::test]
async fn confirmed_logout_unlocks_empty_successor_after_source_cleanup() {
    for source_was_admitted in [true, false] {
        let fixture = Fixture::new(false);
        if !source_was_admitted {
            // A previous release accepted login in the owner but never bound
            // the cleanup-only record. Its confirmed logout remains durable.
            fixture
                .source_store()
                .save(&RuntimeStateV1::empty(&fixture.source_paths, true))
                .unwrap();
        }
        let inventory = || {
            RuntimeRecordInventory::new(
                RuntimeRecordOwner::new(fixture.target_store()),
                vec![RuntimeRecordOwner::new(fixture.source_store())],
            )
        };
        let receipt = logout_receipt(&fixture);
        let writers = RuntimeWriterGates::default();
        let quiescence = writers.quiesce().await;
        *fixture.target.fail_save.lock().unwrap() = true;
        assert!(inventory().complete_logout(&receipt, &quiescence).is_err());
        assert_eq!(
            fixture.source_store().load().unwrap().unwrap(),
            RuntimeStateV1::empty(&fixture.source_paths, false)
        );
        assert!(fixture.target_store().load().unwrap().unwrap().cleanup_only);

        // A new process can finish either interrupted write using the same receipt.
        let restarted = inventory();
        for _ in 0..2 {
            restarted.complete_logout(&receipt, &quiescence).unwrap();
        }
        assert_eq!(
            fixture.target_store().load().unwrap().unwrap(),
            RuntimeStateV1::empty(&fixture.target_paths, false)
        );
        restarted
            .bind_empty_scope(&fixture.scope, &quiescence)
            .unwrap();
    }
}

#[tokio::test]
async fn confirmed_logout_keeps_successor_fenced_when_cleanup_is_unproven() {
    for case in [
        "foreign-source",
        "unbound-source-debt",
        "unbound-source-split",
        "target-scope",
        "target-split",
    ] {
        let fixture = Fixture::new(false);
        let mut receipt = logout_receipt(&fixture);
        let mut target = fixture.target_store().load().unwrap().unwrap();
        match case {
            "foreign-source" => {
                receipt.source.identity.as_mut().unwrap().runtime_version = "0.3.1".into()
            }
            "unbound-source-debt" => {
                let mut source = fixture.source_store().load().unwrap().unwrap();
                source.auth_scope = None;
                source.cleanup_only = true;
                fixture.source_store().save(&source).unwrap();
            }
            "unbound-source-split" => {
                let mut source = RuntimeStateV1::empty(&fixture.source_paths, false);
                source.applied_split_tunnel.working_policy_hash = Some("split".into());
                fixture.source_store().save(&source).unwrap();
            }
            "target-scope" => target.auth_scope = Some(fixture.scope.clone()),
            "target-split" => {
                target.applied_split_tunnel.working_policy_hash = Some("split".into())
            }
            _ => unreachable!(),
        }
        fixture.target_store().save(&target).unwrap();
        let inventory = RuntimeRecordInventory::new(
            RuntimeRecordOwner::new(fixture.target_store()),
            vec![RuntimeRecordOwner::new(fixture.source_store())],
        );
        let writers = RuntimeWriterGates::default();
        let quiescence = writers.quiesce().await;
        assert!(
            inventory.complete_logout(&receipt, &quiescence).is_err(),
            "{case}"
        );
        assert_eq!(
            fixture.target_store().load().unwrap(),
            Some(target),
            "{case}"
        );
    }
}

#[tokio::test]
async fn confirmed_logout_blocks_retained_work_and_preserves_idle_scopes() {
    for (same_record, scope_only) in [(true, false), (false, false), (true, true), (false, true)] {
        let fixture = Fixture::new(same_record);
        if same_record {
            fixture
                .source_store()
                .save(&RuntimeStateV1::empty(&fixture.source_paths, true))
                .unwrap();
        }
        let older_paths =
            RuntimePaths::new(fixture._root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
        let older_record = MemoryRecord::default();
        let older_store = ProtectedRuntimeStore::new(older_record.clone(), older_paths.clone());
        let mut older = RuntimeStateV1::empty(older_store.paths(), false);
        if scope_only {
            let mut scope = fixture.scope.clone();
            scope.identity.runtime_version = older_paths.runtime_version().into();
            scope.identity.container_version = scope.identity.runtime_version.clone();
            older.auth_scope = Some(scope);
        } else {
            older.pending_compensation_stop = Some(pending("older-lease"));
        }
        older_store.save(&older).unwrap();
        let mut retained = vec![RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
            older_record,
            older_paths,
        ))];
        if !same_record {
            retained.push(RuntimeRecordOwner::new(fixture.source_store()));
        }
        let inventory =
            RuntimeRecordInventory::new(RuntimeRecordOwner::new(fixture.target_store()), retained);
        let source_before = fixture.source_store().load().unwrap();
        let target_before = fixture.target_store().load().unwrap();
        let writers = RuntimeWriterGates::default();
        let quiescence = writers.quiesce().await;
        let result = inventory.complete_logout(&logout_receipt(&fixture), &quiescence);
        if scope_only {
            result.unwrap();
            assert_eq!(
                fixture.target_store().load().unwrap(),
                Some(RuntimeStateV1::empty(&fixture.target_paths, false))
            );
        } else {
            assert!(result.is_err());
            assert_eq!(fixture.source_store().load().unwrap(), source_before);
            assert_eq!(fixture.target_store().load().unwrap(), target_before);
        }
        assert_eq!(older_store.load().unwrap(), Some(older));
    }
}
