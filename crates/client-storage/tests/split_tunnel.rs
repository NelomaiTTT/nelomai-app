use nelomai_client_storage::{
    FileSplitTunnelStore, MemorySplitTunnelStore, SplitTunnelStore, StorageError,
    StoredSplitTunnelState,
};
use nelomai_contracts::{
    SplitTunnelApplyResult, SplitTunnelApplyStatus, SplitTunnelMode, SplitTunnelPolicy,
};
use std::fs;
use tempfile::tempdir;

const STATE_LIMIT: usize = 1024 * 1024;

#[test]
fn missing_file_loads_default_and_round_trip_uses_private_state_file() {
    let root = tempdir().unwrap();
    let store = FileSplitTunnelStore::new(root.path());
    assert_eq!(store.load().unwrap(), StoredSplitTunnelState::default());

    let state = populated_state();
    store.save(&state).unwrap();
    assert_eq!(store.load().unwrap(), state);
    assert_eq!(
        store.path(),
        root.path().join("split-tunnel").join("state.json")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(store.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let entries = fs::read_dir(root.path().join("split-tunnel"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, [std::ffi::OsString::from("state.json")]);
}

#[test]
fn malformed_and_oversized_state_are_rejected_without_partial_reads() {
    let root = tempdir().unwrap();
    let store = FileSplitTunnelStore::new(root.path());
    fs::create_dir_all(store.path().parent().unwrap()).unwrap();
    fs::write(store.path(), b"{not-json").unwrap();
    assert!(matches!(store.load(), Err(StorageError::InvalidData(_))));

    fs::write(store.path(), vec![b'x'; STATE_LIMIT + 1]).unwrap();
    assert!(matches!(
        store.load(),
        Err(StorageError::SplitTunnelStateTooLarge { .. })
    ));
}

#[test]
fn oversized_save_keeps_the_previous_working_file() {
    let root = tempdir().unwrap();
    let store = FileSplitTunnelStore::new(root.path());
    let original = populated_state();
    store.save(&original).unwrap();

    let mut oversized = populated_state();
    oversized.cached_policy.as_mut().unwrap().selected_packages = vec!["x".repeat(STATE_LIMIT + 1)];
    assert!(matches!(
        store.save(&oversized),
        Err(StorageError::SplitTunnelStateTooLarge { .. })
    ));
    assert_eq!(store.load().unwrap(), original);
}

#[test]
fn pending_results_keep_at_most_32_and_drop_oldest_successes_first() {
    let root = tempdir().unwrap();
    let store = FileSplitTunnelStore::new(root.path());
    let mut state = StoredSplitTunnelState::default();
    for revision in 0..34 {
        state.pending_apply_results.push(apply_result(
            revision,
            if revision == 0 || revision == 1 {
                SplitTunnelApplyStatus::Failed
            } else {
                SplitTunnelApplyStatus::Applied
            },
        ));
    }

    store.save(&state).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded.pending_apply_results.len(), 32);
    assert_eq!(loaded.pending_apply_results[0].revision, 0);
    assert_eq!(loaded.pending_apply_results[1].revision, 1);
    assert_eq!(loaded.pending_apply_results[2].revision, 4);
}

#[test]
fn memory_store_matches_file_store_delete_and_normalization_semantics() {
    let store = MemorySplitTunnelStore::default();
    let mut state = StoredSplitTunnelState::default();
    for revision in 0..40 {
        state
            .pending_apply_results
            .push(apply_result(revision, SplitTunnelApplyStatus::Applied));
    }

    store.save(&state).unwrap();
    let loaded = store.load().unwrap();
    assert_eq!(loaded.pending_apply_results.len(), 32);
    assert_eq!(loaded.pending_apply_results[0].revision, 8);
    store.delete().unwrap();
    assert_eq!(store.load().unwrap(), StoredSplitTunnelState::default());
}

#[test]
fn debug_output_omits_packages_cidrs_and_apply_error_details() {
    let mut state = populated_state();
    state.pending_apply_results.push(SplitTunnelApplyResult {
        error_code: Some("secret-package-com.example.bank".to_string()),
        ..apply_result(9, SplitTunnelApplyStatus::Failed)
    });

    let debug = format!("{state:?}");
    for secret in [
        "com.example.secret",
        "203.0.113.0/24",
        "secret-package-com.example.bank",
    ] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("pending_apply_results_count"));
}

fn populated_state() -> StoredSplitTunnelState {
    let policy = policy(7);
    StoredSplitTunnelState {
        cached_policy: Some(policy.clone()),
        working_policy_hash: Some(policy.policy_hash.clone()),
        previous_working_policy: Some(policy),
        last_full_sync_unix: Some(1_800_000_000),
        last_revision_check_unix: Some(1_800_000_100),
        last_seen_force_revision: 2,
        pending_apply_results: Vec::new(),
    }
}

fn policy(revision: i64) -> SplitTunnelPolicy {
    SplitTunnelPolicy {
        format_version: 1,
        enabled: true,
        revision,
        force_revision: 2,
        policy_hash: format!("sha256:{}", "a".repeat(64)),
        mode: SplitTunnelMode::ExcludeSelected,
        exclude_local_networks: true,
        mandatory_excluded_packages: vec!["com.example.secret".to_string()],
        suggested_name_fragments: vec!["Example".to_string()],
        selected_packages: vec!["com.example.secret".to_string()],
        excluded_ipv4_cidrs: vec!["203.0.113.0/24".to_string()],
        generated_at: "2026-07-30T12:00:00Z".to_string(),
    }
}

fn apply_result(revision: i64, status: SplitTunnelApplyStatus) -> SplitTunnelApplyResult {
    SplitTunnelApplyResult {
        format_version: 1,
        revision,
        force_revision: 2,
        policy_hash: format!("sha256:{}", "a".repeat(64)),
        status,
        error_code: (status != SplitTunnelApplyStatus::Applied).then(|| "apply_failed".to_string()),
        applied_at: "2026-07-30T12:01:00Z".to_string(),
    }
}
