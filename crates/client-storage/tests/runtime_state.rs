use nelomai_client_storage::RuntimePaths;
use nelomai_client_storage::{
    ProtectedRecordStore, ProtectedRuntimeStore, RuntimeAuthScope, RuntimeRecordOwner,
    RuntimeStateStore, RuntimeStateV1, SplitTunnelStore, StorageError, StoredAuth,
    StoredCompatibility, StoredSplitTunnelState,
};
use nelomai_contracts::RuntimeSlot;
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

#[test]
fn runtime_cache_scope_cannot_be_relabelled_or_inherited_by_a_new_login() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let backend = ProtectedRuntimeStore::new(Raw::default(), paths.clone());
    let mut state = RuntimeStateV1::import_legacy(
        &StoredAuth::new_install(),
        StoredSplitTunnelState::default(),
        &paths,
    );
    let a = RuntimeAuthScope {
        auth_epoch: 1,
        family: "synthetic-family-a".into(),
        identity: nelomai_contracts::RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.16".into(),
            container_version: "0.2.16".into(),
            runtime_contract_version: 1,
            session_generation: Some(1),
        },
    };
    backend.save(&state).unwrap();
    let owner = RuntimeRecordOwner::new(backend);
    assert!(owner.check_scope(&a).is_err());
    assert!(
        owner.bind_empty_scope(&a).is_err(),
        "cleanup_only is not constructor-owned"
    );
    state.complete_legacy_cleanup();
    // Explicit stopped-runtime cleanup authority, not an operational view.
    let backend = ProtectedRuntimeStore::new(Raw::default(), paths);
    backend.save(&state).unwrap();
    let owner = RuntimeRecordOwner::new(backend);
    owner.bind_empty_scope(&a).unwrap();
    let mut stale = owner.operational().load().unwrap().unwrap();
    assert!(owner.check_scope(&a).is_ok());
    let b = RuntimeAuthScope {
        auth_epoch: 3,
        family: "synthetic-family-b".into(),
        ..a.clone()
    };
    owner.bind_empty_scope(&b).unwrap();
    stale.compatibility = Some(StoredCompatibility {
        update_required: false,
        observed_at_unix: 5,
    });
    assert!(
        owner.operational().save(&stale).is_err(),
        "old scope cannot write new family's cache"
    );
    let mut active = owner.operational().load().unwrap().unwrap();
    active.compatibility = stale.compatibility;
    owner.operational().save(&active).unwrap();
    assert!(
        owner.bind_empty_scope(&a).is_err(),
        "any retained runtime payload is quarantined"
    );
    assert!(owner.check_scope(&a).is_err());
    assert!(owner.check_scope(&b).is_ok());
    active.auth_scope = None;
    assert!(owner.operational().save(&active).is_err());
    owner.split().delete().unwrap();
    assert_eq!(
        owner.operational().load().unwrap().unwrap().auth_scope,
        Some(b)
    );
}

#[test]
fn preferences_and_operational_state_have_distinct_exact_namespaces() {
    let root = tempfile::tempdir().unwrap();
    let latest = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let stable = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    assert_eq!(
        latest.preferences,
        root.path().join("runtime/latest/preferences-v1.json")
    );
    assert_eq!(
        latest.operational_state,
        root.path()
            .join("runtime/latest/state/0.2.16/state-v1.json")
    );
    assert_eq!(
        stable.preferences,
        root.path()
            .join("runtime/stable/0.2.16/preferences-v1.json")
    );
    assert_eq!(
        stable.operational_state,
        root.path()
            .join("runtime/stable/state/0.2.16/state-v1.json")
    );
    let newer = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.3.0").unwrap();
    assert_eq!(newer.preferences, latest.preferences);
    assert_ne!(newer.operational_state, latest.operational_state);
}

#[test]
fn another_exact_version_or_slot_cannot_deserialize_old_operational_payload() {
    let root = tempfile::tempdir().unwrap();
    let raw = Raw::default();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let store = ProtectedRuntimeStore::new(raw.clone(), paths.clone());
    let legacy: StoredAuth = serde_json::from_str(
        r#"{"install_secret":"fixed-install","access_token":null,"refresh_token":null}"#,
    )
    .unwrap();
    let state = RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), &paths);
    store.save(&state).unwrap();
    for (slot, version) in [
        (RuntimeSlot::Latest, "0.2.16"),
        (RuntimeSlot::Stable, "0.3.0"),
    ] {
        let other = ProtectedRuntimeStore::new(
            raw.clone(),
            RuntimePaths::new(root.path(), slot, version).unwrap(),
        );
        assert!(other.load().is_err());
        assert!(other.save(&state).is_err());
    }
    assert_eq!(store.load().unwrap(), Some(state));
    assert!(
        !paths.operational_state.exists(),
        "logical path is not a plaintext secret file"
    );
}

#[test]
fn runtime_versions_cannot_escape_the_owned_namespace() {
    let root = tempfile::tempdir().unwrap();
    for version in ["../0.2.16", "0.2.16/next", "0.2.16\\next", "", "0.2.16+.."] {
        assert!(
            RuntimePaths::new(root.path(), RuntimeSlot::Stable, version).is_err(),
            "{version}"
        );
    }
}

#[test]
fn runtime_views_merge_only_owned_fields_in_both_stale_write_orders() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap();
    let raw = Raw::default();
    let backend = ProtectedRuntimeStore::new(raw.clone(), paths.clone());
    let legacy: StoredAuth = serde_json::from_str(
        r#"{"install_secret":"synthetic-install","access_token":null,"refresh_token":null}"#,
    )
    .unwrap();
    let initial = RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), &paths);
    backend.save(&initial).unwrap();
    let owner = RuntimeRecordOwner::new(backend);
    let operational = owner.operational();
    let split = owner.split();
    let mut stale_operational = operational.load().unwrap().unwrap();
    let mut split_value = split.load().unwrap();
    split_value.last_seen_force_revision = 23;
    split.save(&split_value).unwrap();
    stale_operational.compatibility = Some(StoredCompatibility {
        update_required: true,
        observed_at_unix: 41,
    });
    // Neither stale split fields nor the startup-only cleanup barrier are owned
    // by this operational writer.
    stale_operational.cleanup_only = false;
    operational.save(&stale_operational).unwrap();
    assert_eq!(split.load().unwrap().last_seen_force_revision, 23);
    assert!(operational.load().unwrap().unwrap().cleanup_only);

    let mut stale_split = split.load().unwrap();
    let mut next = operational.load().unwrap().unwrap();
    next.compatibility.as_mut().unwrap().observed_at_unix = 52;
    operational.save(&next).unwrap();
    stale_split.last_seen_force_revision = 24;
    split.save(&stale_split).unwrap();
    let final_value = operational.load().unwrap().unwrap();
    assert_eq!(final_value.compatibility.unwrap().observed_at_unix, 52);
    assert_eq!(
        final_value.applied_split_tunnel.last_seen_force_revision,
        24
    );
    split.delete().unwrap();
    let final_value = operational.load().unwrap().unwrap();
    assert_eq!(final_value.compatibility.unwrap().observed_at_unix, 52);
    assert_eq!(
        final_value.applied_split_tunnel,
        StoredSplitTunnelState::default()
    );
    assert!(final_value.cleanup_only);

    for (slot, version) in [
        (RuntimeSlot::Latest, "0.2.16"),
        (RuntimeSlot::Stable, "0.3.0"),
    ] {
        let other = RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
            raw.clone(),
            RuntimePaths::new(root.path(), slot, version).unwrap(),
        ));
        assert!(other.operational().load().is_err());
        assert!(other.split().save(&split_value).is_err());
    }
    assert!(!paths.operational_state.exists());
}

#[test]
fn runtime_views_do_not_create_missing_migration_records() {
    let root = tempfile::tempdir().unwrap();
    let owner = RuntimeRecordOwner::new(ProtectedRuntimeStore::new(
        Raw::default(),
        RuntimePaths::new(root.path(), RuntimeSlot::Stable, "0.2.16").unwrap(),
    ));
    assert!(owner.operational().load().is_err());
    assert!(owner.split().load().is_err());
    assert!(owner
        .split()
        .save(&StoredSplitTunnelState::default())
        .is_err());
}

#[test]
fn exact_cleanup_snapshot_is_sanitized_and_fences_late_runtime_writes() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let backend = ProtectedRuntimeStore::new(Raw::default(), paths.clone());
    let mut legacy: StoredAuth = serde_json::from_str(
        r#"{"install_secret":"synthetic-install","saved_connection":{"lease_id":"lease-a","pool_id":null,"layer":"tic","tic_connection_mode":"dynamic","route_mode":"standalone","egress_mode":"ipv4","probe_url":null,"kind":"fixed","configuration":"PrivateKey = secret","valid_until_unix":null}}"#,
    )
    .unwrap();
    legacy.pending_compensation_stop =
        Some(nelomai_client_storage::StoredPendingCompensationStop {
            operation_id: "legacy-stop".into(),
            lease_id: "lease-b".into(),
            accept_warm: false,
            failure_code: None,
        });
    backend
        .save(&RuntimeStateV1::import_legacy(
            &legacy,
            StoredSplitTunnelState::default(),
            &paths,
        ))
        .unwrap();
    let owner = RuntimeRecordOwner::new(backend);
    let frozen = owner.cleanup_snapshot().unwrap();
    assert_eq!(frozen.lease_ids, ["lease-a", "lease-b"]);
    assert_eq!(frozen.operations[0].operation_id, "legacy-stop");
    assert_eq!(frozen.operations[0].request_fingerprint, None);

    let mut changed = owner.operational().load().unwrap().unwrap();
    changed.saved_connection = None;
    owner.operational().save(&changed).unwrap();
    assert!(owner.complete_cleanup(&frozen).is_err());
    let current = owner.cleanup_snapshot().unwrap();
    owner.complete_cleanup(&current).unwrap();
    let final_state = owner.operational().load().unwrap().unwrap();
    assert!(!final_state.cleanup_only);
    assert!(final_state.operationally_empty());
}
