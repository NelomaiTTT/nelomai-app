use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_api::RuntimeTarget;
use nelomai_client_container::{
    CleanupEngineRoleV1, CleanupEnvelopeV1, CleanupOperationProvenanceV1, CleanupOperationV1,
    SwitchCoordinator, SwitchJournalError, SwitchJournalV1, SwitchPhase,
};
use nelomai_client_storage::{
    ContainerOwnerLock, RuntimeAuthScope, RuntimeCleanupOperationV1, RuntimeCleanupSnapshotV1,
    RuntimePaths, RuntimeStateV1, StoredAuth, StoredConnection, StoredConnectionKind,
    StoredPendingCompensationStop, StoredPendingStart, StoredSplitTunnelState,
};
use nelomai_contracts::{
    verify_container_manifest, ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole,
    RuntimeFileV1, RuntimeIdentity, RuntimeSlot, RuntimeSlotManifestV1,
    CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier};

fn manifest_for(version: &str) -> nelomai_contracts::VerifiedContainerManifest {
    let manifest = ContainerManifestV1 {
        format_version: 1,
        container_version: version.to_owned(),
        release_set_id: format!("runtime-{version}"),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256: None,
        stable_platform_manifest_sha256: None,
        slots: vec![RuntimeSlotManifestV1 {
            slot: RuntimeSlot::Latest,
            manifest: RuntimeArtifactManifestV1 {
                format_version: 1,
                runtime_version: version.to_owned(),
                source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                platform: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                contract_version: 1,
                files: vec![RuntimeFileV1 {
                    path: "bin/nelomai-runtime".to_owned(),
                    size_bytes: 17,
                    sha256: "a".repeat(64),
                    role: RuntimeFileRole::Executable,
                }],
            },
        }],
    };
    let bytes = serde_json::to_vec(&serde_json::to_value(manifest).unwrap()).unwrap();
    let key = SigningKey::from_bytes(&[51; 32]);
    let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    verify_container_manifest(
        &bytes,
        &key.sign(&signed).to_bytes(),
        &key.verifying_key().to_bytes(),
        "linux",
        "x86_64",
    )
    .unwrap()
}

fn manifest() -> nelomai_contracts::VerifiedContainerManifest {
    manifest_for("0.3.0")
}

fn cleanup() -> CleanupEnvelopeV1 {
    CleanupEnvelopeV1 {
        cleanup_contract_version: 1,
        lease_ids: vec!["lease-a".to_owned()],
        redundant_session_ids: vec!["redundant-a".to_owned()],
        operations: vec![CleanupOperationV1 {
            operation_id: "operation-a".to_owned(),
            provenance: CleanupOperationProvenanceV1::Verified {
                request_fingerprint: "a".repeat(64),
                contract_version: 1,
            },
        }],
        engine_role: CleanupEngineRoleV1::Primary,
        background_reference: Some("background-a".to_owned()),
    }
}

fn requested(target: RuntimeTarget) -> SwitchJournalV1 {
    requested_for_operation(target, "11111111-1111-4111-8111-111111111111", cleanup())
}

fn requested_with_cleanup(
    target: RuntimeTarget,
    cleanup_envelope: CleanupEnvelopeV1,
) -> SwitchJournalV1 {
    requested_for_operation(
        target,
        "11111111-1111-4111-8111-111111111111",
        cleanup_envelope,
    )
}

fn requested_for_operation(
    target: RuntimeTarget,
    operation_id: &str,
    cleanup_envelope: CleanupEnvelopeV1,
) -> SwitchJournalV1 {
    SwitchJournalV1::requested(
        operation_id.to_owned(),
        "b".repeat(64),
        Some(RuntimeIdentity {
            slot: RuntimeSlot::Stable,
            runtime_version: "0.2.15".to_owned(),
            runtime_contract_version: 1,
            container_version: "0.2.16".to_owned(),
            session_generation: Some(7),
        }),
        Some("device-a".to_owned()),
        "c".repeat(64),
        target,
        Some(7),
        cleanup_envelope,
    )
}

fn enrolled_journal_with_snapshot(target: RuntimeTarget) -> serde_json::Value {
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Stable,
        runtime_version: "0.2.15".into(),
        runtime_contract_version: 1,
        container_version: "0.2.16".into(),
        session_generation: Some(7),
    };
    let scope = RuntimeAuthScope {
        auth_epoch: 4,
        family: "family-a".into(),
        identity: identity.clone(),
    };
    let snapshot = RuntimeCleanupSnapshotV1 {
        slot: identity.slot,
        runtime_version: identity.runtime_version.clone(),
        auth_scope: Some(scope.clone()),
        lease_ids: vec!["lease-a".into()],
        operations: vec![RuntimeCleanupOperationV1 {
            operation_id: "operation-a".into(),
            request_fingerprint: Some("a".repeat(64)),
            contract_version: Some(1),
        }],
        cleanup_only: false,
    };
    let envelope =
        CleanupEnvelopeV1::from_runtime_snapshot(&snapshot, CleanupEngineRoleV1::Primary, None)
            .unwrap();
    let scope_wire = serde_json::json!({
        "auth_epoch": scope.auth_epoch,
        "family": scope.family,
        "identity": identity,
        "device_id": "device-a",
    });
    let fingerprint = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&scope_wire).unwrap())
    );
    let mut journal = serde_json::to_value(SwitchJournalV1::requested(
        "11111111-1111-4111-8111-111111111111".into(),
        "b".repeat(64),
        Some(scope.identity),
        Some("device-a".into()),
        fingerprint,
        target,
        Some(7),
        envelope,
    ))
    .unwrap();
    journal["runtime_snapshot"] = serde_json::to_value(snapshot).unwrap();
    journal
}

fn requested_with_serialized_len(target: RuntimeTarget, desired: usize) -> SwitchJournalV1 {
    let mut envelope = cleanup();
    envelope.lease_ids = (0..1024).map(|index| format!("l{index:04}")).collect();
    let current = serde_json::to_vec(&requested_with_cleanup(target.clone(), envelope.clone()))
        .unwrap()
        .len();
    assert!(current <= desired);
    let mut remaining = desired - current;
    for lease_id in &mut envelope.lease_ids {
        let added = remaining.min(256 - lease_id.len());
        lease_id.push_str(&"x".repeat(added));
        remaining -= added;
        if remaining == 0 {
            break;
        }
    }
    assert_eq!(remaining, 0, "fixture cannot reach requested wire size");
    let journal = requested_with_cleanup(target, envelope);
    assert_eq!(serde_json::to_vec(&journal).unwrap().len(), desired);
    journal
}

#[test]
fn requested_journal_is_atomic_and_reloads_with_an_obsolete_source_identity() {
    let root = tempfile::tempdir().unwrap();
    let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let manifest = manifest();
    let target =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let journal = requested(target);

    let coordinator = SwitchCoordinator::open(lock.clone(), manifest.clone()).unwrap();
    coordinator.begin_requested(journal.clone()).unwrap();
    assert_eq!(coordinator.snapshot().unwrap(), Some(journal.clone()));
    drop(coordinator);

    let recovered = SwitchCoordinator::open(lock.clone(), manifest).unwrap();
    assert_eq!(recovered.snapshot().unwrap(), Some(journal));
    assert_eq!(
        recovered.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::Requested
    );
}

#[test]
fn accepted_old_target_reloads_after_the_container_manifest_changes() {
    let root = tempfile::tempdir().unwrap();
    let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let old_manifest = manifest_for("0.3.0");
    let old_target =
        RuntimeTarget::from_identity(&old_manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let journal = requested(old_target);
    let old = SwitchCoordinator::open(lock.clone(), old_manifest).unwrap();
    old.begin_requested(journal.clone()).unwrap();
    drop(old);

    let recovered = SwitchCoordinator::open(lock.clone(), manifest_for("0.4.0")).unwrap();
    assert_eq!(recovered.snapshot().unwrap(), Some(journal));
}

#[test]
fn journal_rejects_a_target_not_derived_from_the_current_verified_manifest() {
    let root = tempfile::tempdir().unwrap();
    let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let manifest = manifest();
    let mut wrong_target =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    wrong_target.runtime_version = "9.9.9".to_owned();
    let coordinator = SwitchCoordinator::open(lock.clone(), manifest).unwrap();

    assert!(coordinator
        .begin_requested(requested(wrong_target))
        .is_err());
    assert!(!root.path().join("common/runtime-switch-v1.json").exists());
}

#[test]
fn exact_max_journal_reloads_and_max_plus_one_cannot_replace_it() {
    const EXPECTED_MAX: usize = 256 * 1024;
    let root = tempfile::tempdir().unwrap();
    let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let manifest = manifest();
    let target =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let accepted = requested_with_serialized_len(target.clone(), EXPECTED_MAX);
    let rejected = requested_with_serialized_len(target, EXPECTED_MAX + 1);
    let coordinator = SwitchCoordinator::open(lock.clone(), manifest).unwrap();

    coordinator.begin_requested(accepted.clone()).unwrap();
    drop(coordinator);
    let recovered = SwitchCoordinator::open(lock.clone(), manifest_for("0.3.0")).unwrap();
    assert_eq!(recovered.snapshot().unwrap(), Some(accepted.clone()));
    assert!(matches!(
        recovered.begin_requested(rejected),
        Err(SwitchJournalError::Invalid)
    ));
    assert_eq!(recovered.snapshot().unwrap(), Some(accepted));
}

#[test]
fn recovered_journal_rejects_either_half_of_resume_authority() {
    for (resume_operation_id, decision) in [
        (
            serde_json::json!("22222222-2222-4222-8222-222222222222"),
            serde_json::Value::Null,
        ),
        (serde_json::Value::Null, serde_json::json!("apply")),
    ] {
        let root = tempfile::tempdir().unwrap();
        let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        let manifest = manifest();
        let target =
            RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
        let mut torn = serde_json::to_value(requested(target)).unwrap();
        torn["resume_operation_id"] = resume_operation_id;
        torn["decision"] = decision;
        std::fs::write(
            root.path().join("common/runtime-switch-v1.json"),
            serde_json::to_vec(&torn).unwrap(),
        )
        .unwrap();

        assert!(SwitchCoordinator::open(lock.clone(), manifest).is_err());
    }
}

#[test]
fn recovered_journal_rejects_every_snapshot_source_and_envelope_crosslink_break() {
    let target =
        RuntimeTarget::from_identity(&manifest().identity(RuntimeSlot::Latest, None).unwrap());
    let valid = enrolled_journal_with_snapshot(target);
    type JournalMutation = Box<dyn Fn(&mut serde_json::Value)>;
    let mutations: Vec<JournalMutation> = vec![
        Box::new(|value| value["runtime_snapshot"]["slot"] = serde_json::json!("latest")),
        Box::new(|value| value["runtime_snapshot"]["runtime_version"] = serde_json::json!("9.9.9")),
        Box::new(|value| value["runtime_snapshot"]["cleanup_only"] = serde_json::json!(true)),
        Box::new(|value| {
            value["runtime_snapshot"]["auth_scope"]["family"] = serde_json::json!("family-b")
        }),
        Box::new(|value| value["source_device_id"] = serde_json::json!("device-b")),
        Box::new(|value| {
            value["runtime_snapshot"]["lease_ids"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("extra-lease"))
        }),
        Box::new(|value| {
            value["runtime_snapshot"]["operations"][0]["request_fingerprint"] =
                serde_json::Value::Null
        }),
    ];

    for mutate in mutations {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("common")).unwrap();
        let mut corrupted = valid.clone();
        mutate(&mut corrupted);
        std::fs::write(
            root.path().join("common/runtime-switch-v1.json"),
            serde_json::to_vec(&corrupted).unwrap(),
        )
        .unwrap();
        let lock = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
        assert!(matches!(
            SwitchCoordinator::open(lock, manifest()),
            Err(SwitchJournalError::Invalid)
        ));
    }
}

#[test]
fn coordinators_retain_the_os_owner_and_share_one_same_root_write_gate() {
    let root = tempfile::tempdir().unwrap();
    let owner = Arc::new(ContainerOwnerLock::try_acquire(root.path()).unwrap());
    let first = Arc::new(SwitchCoordinator::open(owner.clone(), manifest()).unwrap());
    let second = Arc::new(SwitchCoordinator::open(owner.clone(), manifest()).unwrap());
    let target =
        RuntimeTarget::from_identity(&manifest().identity(RuntimeSlot::Latest, None).unwrap());
    let first_journal = requested_for_operation(
        target.clone(),
        "11111111-1111-4111-8111-111111111111",
        cleanup(),
    );
    let second_journal =
        requested_for_operation(target, "22222222-2222-4222-8222-222222222222", cleanup());
    drop(owner);
    assert!(ContainerOwnerLock::try_acquire(root.path()).is_err());

    let barrier = Arc::new(Barrier::new(3));
    let first_result = std::thread::scope(|scope| {
        let first_handle = scope.spawn({
            let coordinator = first.clone();
            let barrier = barrier.clone();
            let journal = first_journal.clone();
            move || {
                barrier.wait();
                coordinator.begin_requested(journal)
            }
        });
        let second_handle = scope.spawn({
            let coordinator = second.clone();
            let barrier = barrier.clone();
            let journal = second_journal.clone();
            move || {
                barrier.wait();
                coordinator.begin_requested(journal)
            }
        });
        barrier.wait();
        (first_handle.join().unwrap(), second_handle.join().unwrap())
    });
    assert_eq!(
        usize::from(first_result.0.is_ok()) + usize::from(first_result.1.is_ok()),
        1
    );
    assert!(matches!(
        first_result.0,
        Ok(()) | Err(SwitchJournalError::Pending)
    ));
    assert!(matches!(
        first_result.1,
        Ok(()) | Err(SwitchJournalError::Pending)
    ));
    let winner = first.snapshot().unwrap().unwrap();
    assert!(winner == first_journal || winner == second_journal);

    drop(first);
    drop(second);
    assert!(ContainerOwnerLock::try_acquire(root.path()).is_ok());
}

#[test]
fn cleanup_envelope_round_trips_without_a_secret_or_tunnel_configuration_surface() {
    let envelope = cleanup();
    let bytes = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        serde_json::from_slice::<CleanupEnvelopeV1>(&bytes).unwrap(),
        envelope
    );
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in [
        "configuration",
        "private_key",
        "access_token",
        "refresh_token",
        "install_secret",
        "secret-value",
    ] {
        assert!(!text.contains(forbidden));
    }

    let mut value = serde_json::to_value(cleanup()).unwrap();
    value["configuration"] = serde_json::json!("secret-value");
    assert!(serde_json::from_value::<CleanupEnvelopeV1>(value).is_err());
}

#[test]
fn public_cleanup_projection_rejects_every_secret_marker_and_oversized_aggregate() {
    for marker in [
        "PrivateKey=value",
        "private_key=value",
        "access_token=value",
        "refresh_token=value",
        "install_secret=value",
        "Authorization: value",
        "Bearer value",
        "[Interface]",
    ] {
        let snapshot = RuntimeCleanupSnapshotV1 {
            slot: RuntimeSlot::Latest,
            runtime_version: "0.2.16".into(),
            auth_scope: None,
            lease_ids: vec![marker.into()],
            operations: Vec::new(),
            cleanup_only: true,
        };
        assert!(CleanupEnvelopeV1::from_runtime_snapshot(
            &snapshot,
            CleanupEngineRoleV1::Primary,
            None,
        )
        .is_err());
    }

    let snapshot = RuntimeCleanupSnapshotV1 {
        slot: RuntimeSlot::Latest,
        runtime_version: "0.2.16".into(),
        auth_scope: None,
        lease_ids: (0..1024)
            .map(|index| format!("{index:04}{}", "x".repeat(252)))
            .collect(),
        operations: Vec::new(),
        cleanup_only: true,
    };
    assert!(CleanupEnvelopeV1::from_runtime_snapshot(
        &snapshot,
        CleanupEngineRoleV1::Primary,
        None,
    )
    .is_err());
}

#[test]
fn actual_runtime_record_projects_known_and_legacy_unknown_cleanup_without_secrets() {
    let root = tempfile::tempdir().unwrap();
    let paths = RuntimePaths::new(root.path(), RuntimeSlot::Latest, "0.2.16").unwrap();
    let mut legacy = StoredAuth::new_install();
    legacy.saved_connection = Some(StoredConnection {
        lease_id: "lease-current".into(),
        pool_id: None,
        layer: nelomai_contracts::Layer::Tic,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        probe_url: None,
        kind: StoredConnectionKind::Fixed,
        configuration: "PrivateKey = forbidden-secret".into(),
        valid_until_unix: None,
    });
    legacy.pending_start = Some(StoredPendingStart {
        operation_id: "legacy-start".into(),
        layer: nelomai_contracts::Layer::Tic,
        tic_connection_mode: nelomai_contracts::TicConnectionMode::Dynamic,
        route_mode: nelomai_contracts::RouteMode::Standalone,
        egress_mode: nelomai_contracts::EgressMode::Ipv4,
        allow_alternate: true,
        probes: Vec::new(),
        recovery_contract_version: None,
        request_fingerprint: None,
        cancel_operation_id: None,
    });
    legacy.pending_compensation_stop = Some(StoredPendingCompensationStop {
        operation_id: "legacy-stop".into(),
        lease_id: "lease-pending".into(),
        accept_warm: false,
        failure_code: None,
    });
    let state = RuntimeStateV1::import_legacy(&legacy, StoredSplitTunnelState::default(), &paths);

    let envelope = CleanupEnvelopeV1::from_runtime_state(
        &state,
        CleanupEngineRoleV1::Primary,
        Some("background-a".into()),
    )
    .unwrap();
    assert_eq!(envelope.lease_ids, ["lease-current", "lease-pending"]);
    assert_eq!(
        envelope.operations,
        [
            CleanupOperationV1 {
                operation_id: "legacy-start".into(),
                provenance: CleanupOperationProvenanceV1::LegacyUnknown,
            },
            CleanupOperationV1 {
                operation_id: "legacy-stop".into(),
                provenance: CleanupOperationProvenanceV1::LegacyUnknown,
            },
        ]
    );
    let bytes = serde_json::to_string(&envelope).unwrap();
    for forbidden in [
        "PrivateKey",
        "forbidden-secret",
        "configuration",
        "install_secret",
    ] {
        assert!(!bytes.contains(forbidden));
    }
}
