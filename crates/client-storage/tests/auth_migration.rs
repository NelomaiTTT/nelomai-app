use nelomai_client_storage::*;
use nelomai_contracts::{RuntimeIdentity, RuntimeSlot};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Raw(
    Arc<Mutex<Option<Vec<u8>>>>,
    Arc<Mutex<Option<bool>>>,
    Arc<Mutex<bool>>,
);
impl ProtectedRecordStore for Raw {
    fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save_record(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let failure = self.1.lock().unwrap().take();
        if failure == Some(false) {
            return Err(StorageError::RecoveryRequired("injected write crash"));
        }
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        if failure == Some(true) {
            return Err(StorageError::RecoveryRequired("injected write crash"));
        }
        Ok(())
    }
    fn delete_record(&self) -> Result<(), StorageError> {
        if std::mem::take(&mut *self.2.lock().unwrap()) {
            return Err(StorageError::RecoveryRequired(
                "injected staging clear crash",
            ));
        }
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
#[derive(Default)]
struct Legacy(Mutex<Option<StoredAuth>>);
impl SecretStore for Legacy {
    fn load(&self) -> Result<Option<StoredAuth>, StorageError> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, value: &StoredAuth) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = Some(value.clone());
        Ok(())
    }
    fn delete(&self) -> Result<(), StorageError> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}
fn legacy_auth() -> StoredAuth {
    serde_json::from_value(serde_json::json!({
        "install_secret":"unchanged-install", "access_token":"legacy-access", "refresh_token":"legacy-refresh",
        "saved_connection": {"lease_id":"lease-a","pool_id":"pool","layer":"tic","tic_connection_mode":"dynamic","route_mode":"via_tak","kind":"dynamic_warm","configuration":"PRIVATE-TUNNEL-CONFIG","valid_until_unix":1900000000},
        "pinned_connection": {"lease_id":"lease-b","layer":"tic","tic_connection_mode":"dynamic","route_mode":"via_tak","kind":"pinned","configuration":"PRIVATE-PINNED-CONFIG","valid_until_unix":null},
        "pending_start":{"operation_id":"start-a","layer":"tic","tic_connection_mode":"dynamic","route_mode":"via_tak","recovery_contract_version":1,"request_fingerprint":"fingerprint-a"},
        "pending_stalled_stop":{"operation_id":"stop-a","lease_id":"lease-a","contract_version":1,"request_fingerprint":"fingerprint-stop"},
        "pending_compensation_stop":{"operation_id":"compensate-a","lease_id":"lease-b","accept_warm":true,"failure_code":"retry"},
        "compatibility":{"update_required":true,"observed_at_unix":1700000000}
    })).unwrap()
}
fn split_state() -> StoredSplitTunnelState {
    StoredSplitTunnelState {
        working_policy_hash: Some("applied-policy".into()),
        last_full_sync_unix: Some(123),
        last_seen_force_revision: 9,
        ..Default::default()
    }
}
struct CrashJournal {
    inner: FileMigrationJournal,
    crash: Mutex<Option<MigrationPhase>>,
}
impl MigrationJournal for CrashJournal {
    fn load(&self) -> Result<Option<MigrationRecord>, StorageError> {
        self.inner.load()
    }
    fn save(&self, record: &MigrationRecord) -> Result<(), StorageError> {
        self.inner.save(record)?;
        let mut crash = self.crash.lock().unwrap();
        if *crash == Some(record.phase) {
            *crash = None;
            return Err(StorageError::RecoveryRequired("injected crash"));
        }
        Ok(())
    }
}

#[test]
fn every_migration_phase_resumes_twice_without_replacing_install_or_tokens() {
    for phase in [
        MigrationPhase::LegacyRead,
        MigrationPhase::AuthWritten,
        MigrationPhase::RuntimeWritten,
        MigrationPhase::Committed,
        MigrationPhase::Verified,
    ] {
        let root = tempfile::tempdir().unwrap();
        let legacy = Legacy(Mutex::new(Some(legacy_auth())));
        let split = MemorySplitTunnelStore::default();
        split.save(&split_state()).unwrap();
        let source = LegacyMigrationSource::new(&legacy, &split);
        let auth = ProtectedAuthStore::new(Raw::default());
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let runtime = ProtectedRuntimeStore::new(Raw::default(), paths);
        let journal = CrashJournal {
            inner: FileMigrationJournal::new(root.path().join("migration.json")),
            crash: Mutex::new(Some(phase)),
        };
        assert!(migrate_legacy_auth(&source, &auth, &runtime, &journal).is_err());
        for _ in 0..2 {
            assert_eq!(
                migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap(),
                MigrationOutcome::AwaitingBootstrap
            );
        }
        let value = auth.load().unwrap().unwrap();
        assert_eq!(value.install_secret, "unchanged-install");
        assert_eq!(value.access_token.as_deref(), Some("legacy-access"));
        assert_eq!(value.refresh_token.as_deref(), Some("legacy-refresh"));
        assert_eq!(value.session_generation, None);
        assert_eq!(value.auth_epoch, 0);
        let state = runtime.load().unwrap().unwrap();
        assert!(state.cleanup_only);
        assert!(!state.start_or_recovery_allowed());
        assert_eq!(state.saved_connection, legacy_auth().saved_connection);
        assert_eq!(state.pinned_connection, legacy_auth().pinned_connection);
        assert_eq!(state.pending_start, legacy_auth().pending_start);
        assert_eq!(
            state.pending_stalled_stop,
            legacy_auth().pending_stalled_stop
        );
        assert_eq!(
            state.pending_compensation_stop,
            legacy_auth().pending_compensation_stop
        );
        assert_eq!(state.compatibility, legacy_auth().compatibility);
        assert_eq!(state.applied_split_tunnel, split_state());
        assert_eq!(legacy.load().unwrap(), Some(legacy_auth()));
    }
}

#[test]
fn corrupted_new_auth_does_not_overwrite_intact_legacy_or_create_install() {
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy(Mutex::new(Some(legacy_auth())));
    let split = MemorySplitTunnelStore::default();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let raw = Raw::default();
    let auth = ProtectedAuthStore::new(raw.clone());
    auth.save(&AuthStoreV1::from_legacy(&legacy_auth()))
        .unwrap();
    let mut corrupted: serde_json::Value =
        serde_json::from_slice(&raw.load_record().unwrap().unwrap()).unwrap();
    corrupted["checksum"] = serde_json::Value::String("f".repeat(64));
    raw.save_record(&serde_json::to_vec(&corrupted).unwrap())
        .unwrap();
    assert!(auth.load().is_err());
    let runtime = ProtectedRuntimeStore::new(
        Raw::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
    );
    let journal = FileMigrationJournal::new(root.path().join("migration.json"));
    assert!(migrate_legacy_auth(&source, &auth, &runtime, &journal).is_err());
    assert_eq!(legacy.load().unwrap(), Some(legacy_auth()));
    let staging = ProtectedTransactionStore::new(Raw::default(), runtime.paths().clone());
    assert!(
        RuntimeStorageSession::new(&auth, &runtime, &journal, &staging)
            .load()
            .is_err()
    );
}

#[test]
fn fresh_adapter_replays_protected_target_after_each_owner_write_crash() {
    for (owner, after) in [
        ("staging", false),
        ("staging", true),
        ("auth", false),
        ("auth", true),
        ("runtime", false),
        ("runtime", true),
        ("clear", false),
    ] {
        let root = tempfile::tempdir().unwrap();
        let legacy = Legacy(Mutex::new(Some(legacy_auth())));
        let split = MemorySplitTunnelStore::default();
        let source = LegacyMigrationSource::new(&legacy, &split);
        let auth_raw = Raw::default();
        let runtime_raw = Raw::default();
        let stage_raw = Raw::default();
        let auth = ProtectedAuthStore::new(auth_raw.clone());
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let runtime = ProtectedRuntimeStore::new(runtime_raw.clone(), paths.clone());
        let staging = ProtectedTransactionStore::new(stage_raw.clone(), paths);
        let journal = FileMigrationJournal::new(root.path().join("journal.json"));
        migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
        let mut clean = runtime.load().unwrap().unwrap();
        clean.complete_legacy_cleanup();
        runtime.save(&clean).unwrap();
        let before = auth.load().unwrap().unwrap();
        let adapter = RuntimeStorageSession::new(&auth, &runtime, &journal, &staging);
        let mut projection = adapter.load().unwrap().unwrap();
        projection.access_token = Some("intended-access".into());
        projection.refresh_token = Some("intended-refresh".into());
        projection.saved_connection = legacy_auth().saved_connection;
        match owner {
            "staging" => *stage_raw.1.lock().unwrap() = Some(after),
            "auth" => *auth_raw.1.lock().unwrap() = Some(after),
            "runtime" => *runtime_raw.1.lock().unwrap() = Some(after),
            "clear" => *stage_raw.2.lock().unwrap() = true,
            _ => unreachable!(),
        };
        assert!(adapter.save(&projection).is_err());
        let fresh = RuntimeStorageSession::new(&auth, &runtime, &journal, &staging);
        let recovered = fresh.load().unwrap().unwrap();
        if owner == "staging" && !after {
            assert_eq!(recovered.access_token, before.access_token);
        } else {
            assert_eq!(recovered, projection);
        }
        assert!(staging.load().unwrap().is_none());
        assert!(journal.load().unwrap().unwrap().pending_write.is_none());
        assert_eq!(auth.load().unwrap().unwrap().auth_epoch, before.auth_epoch);
        let plain = std::fs::read_to_string(root.path().join("journal.json")).unwrap();
        for secret in [
            "intended-access",
            "intended-refresh",
            "PRIVATE-TUNNEL-CONFIG",
        ] {
            assert!(!plain.contains(secret));
        }
    }
}

#[test]
fn bootstrap_ack_tombstones_legacy_only_after_durable_server_enrollment() {
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy(Mutex::new(Some(legacy_auth())));
    let split = MemorySplitTunnelStore::default();
    split.save(&split_state()).unwrap();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let raw = Raw::default();
    let auth = ProtectedAuthStore::new(raw.clone());
    let runtime = ProtectedRuntimeStore::new(
        Raw::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
    );
    let path = root.path().join("migration.json");
    let journal = FileMigrationJournal::new(&path);
    migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
    assert!(acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).is_err());
    let mut value = auth.load().unwrap().unwrap();
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.16".into(),
        runtime_contract_version: 1,
        container_version: "0.3.0".into(),
        session_generation: Some(41),
    };
    value.pending_resume = Some(PendingResumeV1 {
        operation_id: "resume-operation".into(),
        fingerprint: "f".repeat(64),
        target_identity: identity.clone(),
        result: Some(ResumeResultV1 {
            identity: identity.clone(),
            access_token: "returned-access".into(),
        }),
    });
    value.access_token = Some("returned-access".into());
    value.session_generation = Some(41);
    value.confirmed_identity = Some(identity);
    value.auth_epoch = 9;
    auth.save(&value).unwrap();
    for _ in 0..2 {
        migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
        assert_eq!(auth.load().unwrap(), Some(value.clone()));
    }
    let mut state = runtime.load().unwrap().unwrap();
    state.complete_legacy_cleanup();
    runtime.save(&state).unwrap();
    acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).unwrap();
    acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).unwrap();
    let tombstone = legacy.load().unwrap().unwrap();
    assert_eq!(tombstone.install_secret, "unchanged-install");
    assert!(tombstone.access_token.is_none());
    assert!(tombstone.refresh_token.is_none());
    assert!(tombstone.saved_connection.is_none());
    assert!(tombstone.pending_start.is_none());
    assert_eq!(
        serde_json::from_slice::<StoredAuth>(&serde_json::to_vec(&tombstone).unwrap()).unwrap(),
        tombstone
    );
    assert_eq!(split.load().unwrap(), StoredSplitTunnelState::default());
    let plain = std::fs::read_to_string(path).unwrap();
    for secret in [
        "unchanged-install",
        "legacy-access",
        "legacy-refresh",
        "returned-access",
        "PRIVATE-TUNNEL-CONFIG",
    ] {
        assert!(!plain.contains(secret));
        assert!(!format!("{value:?}").contains(secret));
    }
    assert!(String::from_utf8(raw.load_record().unwrap().unwrap())
        .unwrap()
        .contains("returned-access"));
}

#[test]
fn bootstrap_ack_does_not_destroy_legacy_changed_after_migration() {
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy(Mutex::new(Some(legacy_auth())));
    let split = MemorySplitTunnelStore::default();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let auth = ProtectedAuthStore::new(Raw::default());
    let runtime = ProtectedRuntimeStore::new(
        Raw::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
    );
    let journal = FileMigrationJournal::new(root.path().join("journal.json"));
    migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
    let mut value = auth.load().unwrap().unwrap();
    value.session_generation = Some(41);
    value.confirmed_identity = Some(RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.16".into(),
        container_version: "0.3.0".into(),
        runtime_contract_version: 1,
        session_generation: Some(41),
    });
    auth.save(&value).unwrap();
    let mut state = runtime.load().unwrap().unwrap();
    state.complete_legacy_cleanup();
    runtime.save(&state).unwrap();
    let mut changed = legacy_auth();
    changed.access_token = Some("newer-legacy-login".into());
    legacy.save(&changed).unwrap();
    assert!(acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).is_err());
    assert_eq!(legacy.load().unwrap(), Some(changed));
}

#[test]
fn stale_staging_cannot_rollback_later_broker_enrollment_or_epoch() {
    for committed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let legacy = Legacy(Mutex::new(Some(legacy_auth())));
        let split = MemorySplitTunnelStore::default();
        let source = LegacyMigrationSource::new(&legacy, &split);
        let auth = ProtectedAuthStore::new(Raw::default());
        let runtime_raw = Raw::default();
        let stage_raw = Raw::default();
        let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
        let runtime = ProtectedRuntimeStore::new(runtime_raw.clone(), paths.clone());
        let staging = ProtectedTransactionStore::new(stage_raw.clone(), paths);
        let journal = FileMigrationJournal::new(root.path().join("journal.json"));
        migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
        let mut state = runtime.load().unwrap().unwrap();
        state.complete_legacy_cleanup();
        runtime.save(&state).unwrap();
        let adapter = RuntimeStorageSession::new(&auth, &runtime, &journal, &staging);
        let mut old = adapter.load().unwrap().unwrap();
        old.access_token = Some("old-target".into());
        old.saved_connection = legacy_auth().saved_connection;
        if committed {
            *stage_raw.2.lock().unwrap() = true;
        } else {
            *runtime_raw.1.lock().unwrap() = Some(false);
        }
        assert!(adapter.save(&old).is_err());
        let mut newer = auth.load().unwrap().unwrap();
        newer.auth_epoch = 10;
        newer.session_generation = Some(99);
        newer.confirmed_identity = Some(RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            container_version: "0.3.0".into(),
            runtime_contract_version: 1,
            session_generation: Some(99),
        });
        newer.access_token = Some("newer-access".into());
        auth.save(&newer).unwrap();
        let fresh = RuntimeStorageSession::new(&auth, &runtime, &journal, &staging);
        if committed {
            assert_eq!(
                fresh.load().unwrap().unwrap().access_token,
                newer.access_token
            );
            assert!(staging.load().unwrap().is_none());
        } else {
            assert!(fresh.load().is_err());
            assert!(staging.load().unwrap().is_some());
        }
        assert_eq!(auth.load().unwrap(), Some(newer));
    }
}

#[test]
fn adapter_preserves_broker_metadata_and_rejects_stale_cancellation_epoch() {
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy(Mutex::new(Some(legacy_auth())));
    let split = MemorySplitTunnelStore::default();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let auth = ProtectedAuthStore::new(Raw::default());
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let runtime = ProtectedRuntimeStore::new(Raw::default(), paths.clone());
    let staging = ProtectedTransactionStore::new(Raw::default(), paths);
    let journal = FileMigrationJournal::new(root.path().join("journal.json"));
    migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
    let mut state = runtime.load().unwrap().unwrap();
    state.complete_legacy_cleanup();
    runtime.save(&state).unwrap();
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.16".into(),
        container_version: "0.3.0".into(),
        runtime_contract_version: 1,
        session_generation: Some(41),
    };
    let mut owner = auth.load().unwrap().unwrap();
    owner.auth_epoch = 8;
    owner.session_generation = Some(41);
    owner.confirmed_identity = Some(identity.clone());
    owner.pending_resume = Some(PendingResumeV1 {
        operation_id: "resume".into(),
        fingerprint: "f".repeat(64),
        target_identity: identity.clone(),
        result: Some(ResumeResultV1 {
            identity,
            access_token: "durable-result".into(),
        }),
    });
    auth.save(&owner).unwrap();
    let adapter = RuntimeStorageSession::new(&auth, &runtime, &journal, &staging);
    let mut projected = adapter.load().unwrap().unwrap();
    projected.access_token = Some("refreshed-access".into());
    adapter.save(&projected).unwrap();
    let saved = auth.load().unwrap().unwrap();
    assert_eq!(saved.auth_epoch, 8);
    assert_eq!(saved.session_generation, Some(41));
    assert_eq!(saved.pending_resume, owner.pending_resume);
    assert_eq!(saved.confirmed_identity, owner.confirmed_identity);
    let mut cancelled = saved;
    cancelled.auth_epoch = 9;
    cancelled.logout_state = LogoutState::Pending;
    auth.save(&cancelled).unwrap();
    assert!(adapter.save(&projected).is_err());
    assert_eq!(auth.load().unwrap(), Some(cancelled));
}

#[test]
fn migration_owner_write_failures_resume_without_claiming_completion_early() {
    for (owner, after) in [
        ("auth", false),
        ("auth", true),
        ("runtime", false),
        ("runtime", true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let legacy = Legacy(Mutex::new(Some(legacy_auth())));
        let split = MemorySplitTunnelStore::default();
        split.save(&split_state()).unwrap();
        let source = LegacyMigrationSource::new(&legacy, &split);
        let auth_raw = Raw::default();
        let runtime_raw = Raw::default();
        let auth = ProtectedAuthStore::new(auth_raw.clone());
        let runtime = ProtectedRuntimeStore::new(
            runtime_raw.clone(),
            RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
        );
        let journal = FileMigrationJournal::new(root.path().join("journal.json"));
        if owner == "auth" {
            *auth_raw.1.lock().unwrap() = Some(after);
        } else {
            *runtime_raw.1.lock().unwrap() = Some(after);
        }
        assert!(migrate_legacy_auth(&source, &auth, &runtime, &journal).is_err());
        assert!(!matches!(
            journal.load().unwrap().unwrap().phase,
            MigrationPhase::Verified | MigrationPhase::Complete
        ));
        for _ in 0..2 {
            assert_eq!(
                migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap(),
                MigrationOutcome::AwaitingBootstrap
            );
        }
        assert_eq!(
            auth.load().unwrap().unwrap().install_secret,
            "unchanged-install"
        );
        assert_eq!(
            runtime.load().unwrap().unwrap().applied_split_tunnel,
            split_state()
        );
    }
}

#[test]
fn unavailable_or_missing_records_never_look_like_an_empty_install() {
    struct Unavailable;
    impl ProtectedRecordStore for Unavailable {
        fn load_record(&self) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::Keyring("synthetic unavailable".into()))
        }
        fn save_record(&self, _: &[u8]) -> Result<(), StorageError> {
            unreachable!()
        }
        fn delete_record(&self) -> Result<(), StorageError> {
            unreachable!()
        }
    }
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy(Mutex::new(Some(legacy_auth())));
    let split = MemorySplitTunnelStore::default();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let auth = ProtectedAuthStore::new(Unavailable);
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let runtime = ProtectedRuntimeStore::new(Raw::default(), paths.clone());
    let staging = ProtectedTransactionStore::new(Raw::default(), paths);
    let journal = FileMigrationJournal::new(root.path().join("journal.json"));
    assert!(migrate_legacy_auth(&source, &auth, &runtime, &journal).is_err());
    assert!(
        RuntimeStorageSession::new(&auth, &runtime, &journal, &staging)
            .load()
            .is_err()
    );
    let empty = ProtectedAuthStore::new(Raw::default());
    assert!(
        RuntimeStorageSession::new(&empty, &runtime, &journal, &staging)
            .load()
            .is_err()
    );
    assert_eq!(legacy.load().unwrap(), Some(legacy_auth()));
}

#[test]
fn orphaned_legacy_split_state_is_not_a_fresh_install() {
    let root = tempfile::tempdir().unwrap();
    let legacy = Legacy::default();
    let split = MemorySplitTunnelStore::default();
    split.save(&split_state()).unwrap();
    let source = LegacyMigrationSource::new(&legacy, &split);
    let auth = ProtectedAuthStore::new(Raw::default());
    let runtime = ProtectedRuntimeStore::new(
        Raw::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
    );
    let journal = FileMigrationJournal::new(root.path().join("journal.json"));
    assert!(migrate_legacy_auth(&source, &auth, &runtime, &journal).is_err());
    assert_eq!(split.load().unwrap(), split_state());
    assert!(auth.load().unwrap().is_none());
}

#[test]
fn tombstone_commit_replays_after_both_journal_boundaries() {
    for phase in [MigrationPhase::Tombstoning, MigrationPhase::Complete] {
        let root = tempfile::tempdir().unwrap();
        let legacy = Legacy(Mutex::new(Some(legacy_auth())));
        let split = MemorySplitTunnelStore::default();
        split.save(&split_state()).unwrap();
        let source = LegacyMigrationSource::new(&legacy, &split);
        let auth = ProtectedAuthStore::new(Raw::default());
        let runtime = ProtectedRuntimeStore::new(
            Raw::default(),
            RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
        );
        let path = root.path().join("journal.json");
        let journal = CrashJournal {
            inner: FileMigrationJournal::new(&path),
            crash: Mutex::new(None),
        };
        migrate_legacy_auth(&source, &auth, &runtime, &journal).unwrap();
        let mut value = auth.load().unwrap().unwrap();
        value.session_generation = Some(41);
        value.confirmed_identity = Some(RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            container_version: "0.3.0".into(),
            runtime_contract_version: 1,
            session_generation: Some(41),
        });
        auth.save(&value).unwrap();
        let mut state = runtime.load().unwrap().unwrap();
        state.complete_legacy_cleanup();
        runtime.save(&state).unwrap();
        *journal.crash.lock().unwrap() = Some(phase);
        assert!(acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).is_err());
        for _ in 0..2 {
            assert_eq!(
                acknowledge_migration_bootstrap(&source, &auth, &runtime, &journal).unwrap(),
                MigrationOutcome::Complete
            );
        }
        assert_eq!(
            legacy.load().unwrap().unwrap().install_secret,
            "unchanged-install"
        );
        assert!(legacy.load().unwrap().unwrap().refresh_token.is_none());
        assert_eq!(auth.load().unwrap(), Some(value));
        assert_eq!(split.load().unwrap(), StoredSplitTunnelState::default());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
