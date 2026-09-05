use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_api::RuntimeTarget;
use nelomai_client_container::{
    CleanupEngineRoleV1, CleanupEnvelopeV1, CleanupOperationV1, SwitchCoordinator, SwitchJournalV1,
    SwitchPhase,
};
use nelomai_client_storage::ContainerOwnerLock;
use nelomai_contracts::{
    verify_container_manifest, ContainerManifestV1, RuntimeArtifactManifestV1, RuntimeFileRole,
    RuntimeFileV1, RuntimeIdentity, RuntimeSlot, RuntimeSlotManifestV1,
    CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};

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
            request_fingerprint: "a".repeat(64),
            contract_version: 1,
        }],
        engine_role: CleanupEngineRoleV1::Primary,
        background_reference: Some("background-a".to_owned()),
    }
}

fn requested(target: RuntimeTarget) -> SwitchJournalV1 {
    SwitchJournalV1::requested(
        "11111111-1111-4111-8111-111111111111".to_owned(),
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
        cleanup(),
    )
}

#[test]
fn requested_journal_is_atomic_and_reloads_with_an_obsolete_source_identity() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let manifest = manifest();
    let target =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let journal = requested(target);

    let coordinator = SwitchCoordinator::open(&lock, manifest.clone()).unwrap();
    coordinator.begin_requested(journal.clone()).unwrap();
    assert_eq!(coordinator.snapshot().unwrap(), Some(journal.clone()));
    drop(coordinator);

    let recovered = SwitchCoordinator::open(&lock, manifest).unwrap();
    assert_eq!(recovered.snapshot().unwrap(), Some(journal));
    assert_eq!(
        recovered.snapshot().unwrap().unwrap().phase(),
        SwitchPhase::Requested
    );
}

#[test]
fn accepted_old_target_reloads_after_the_container_manifest_changes() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let old_manifest = manifest_for("0.3.0");
    let old_target =
        RuntimeTarget::from_identity(&old_manifest.identity(RuntimeSlot::Latest, None).unwrap());
    let journal = requested(old_target);
    let old = SwitchCoordinator::open(&lock, old_manifest).unwrap();
    old.begin_requested(journal.clone()).unwrap();
    drop(old);

    let recovered = SwitchCoordinator::open(&lock, manifest_for("0.4.0")).unwrap();
    assert_eq!(recovered.snapshot().unwrap(), Some(journal));
}

#[test]
fn journal_rejects_a_target_not_derived_from_the_current_verified_manifest() {
    let root = tempfile::tempdir().unwrap();
    let lock = ContainerOwnerLock::try_acquire(root.path()).unwrap();
    let manifest = manifest();
    let mut wrong_target =
        RuntimeTarget::from_identity(&manifest.identity(RuntimeSlot::Latest, None).unwrap());
    wrong_target.runtime_version = "9.9.9".to_owned();
    let coordinator = SwitchCoordinator::open(&lock, manifest).unwrap();

    assert!(coordinator
        .begin_requested(requested(wrong_target))
        .is_err());
    assert!(!root.path().join("common/runtime-switch-v1.json").exists());
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
