use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::{
    verify_container_manifest, verify_runtime_artifact_manifest,
    verify_runtime_release_set_manifest, ContainerManifestV1, RuntimeArtifactManifestV1,
    RuntimeFileRole, RuntimeFileV1, RuntimeIdentity, RuntimeManifestError,
    RuntimeReleaseArtifactV1, RuntimeReleaseSetManifestV1, RuntimeSlot, RuntimeSlotManifestV1,
    CONTAINER_MANIFEST_SIGNATURE_DOMAIN, RUNTIME_MANIFEST_SIGNATURE_DOMAIN,
    RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN,
};
use serde::Serialize;
use serde_json::{json, Value};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn public_key() -> [u8; 32] {
    signing_key().verifying_key().to_bytes()
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(&serde_json::to_value(value).unwrap()).unwrap()
}

fn sign(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    signing_key().sign(&message).to_bytes().to_vec()
}

fn file(path: &str, hash_byte: char) -> RuntimeFileV1 {
    RuntimeFileV1 {
        path: path.to_owned(),
        size_bytes: 17,
        sha256: hash_byte.to_string().repeat(64),
        role: RuntimeFileRole::Executable,
    }
}

fn artifact(version: &str, platform: &str, architecture: &str) -> RuntimeArtifactManifestV1 {
    RuntimeArtifactManifestV1 {
        format_version: 1,
        runtime_version: version.to_owned(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        platform: platform.to_owned(),
        architecture: architecture.to_owned(),
        contract_version: 1,
        files: vec![file("bin/nelomai-runtime", 'a')],
    }
}

fn container() -> ContainerManifestV1 {
    ContainerManifestV1 {
        format_version: 1,
        container_version: "0.2.16".to_owned(),
        release_set_id: "runtime-0.2.16".to_owned(),
        minimum_runtime_contract: 1,
        maximum_runtime_contract: 1,
        stable_release_set_sha256: None,
        stable_platform_manifest_sha256: None,
        slots: vec![RuntimeSlotManifestV1 {
            slot: RuntimeSlot::Latest,
            manifest: artifact("0.2.16", "linux", "x86_64"),
        }],
    }
}

fn verify_container(
    manifest: &ContainerManifestV1,
) -> Result<nelomai_contracts::VerifiedContainerManifest, RuntimeManifestError> {
    let bytes = canonical(manifest);
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    verify_container_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
}

fn root_entry(platform: &str, architecture: &str, marker: char) -> RuntimeReleaseArtifactV1 {
    RuntimeReleaseArtifactV1 {
        platform: platform.to_owned(),
        architecture: architecture.to_owned(),
        archive_name: format!("nelomai-runtime-{platform}-{architecture}.tar.zst"),
        archive_sha256: marker.to_string().repeat(64),
        manifest_name: format!("nelomai-runtime-{platform}-{architecture}.json"),
        manifest_sha256: ((marker as u8 + 1) as char).to_string().repeat(64),
        signature_name: format!("nelomai-runtime-{platform}-{architecture}.sig"),
        signature_sha256: ((marker as u8 + 2) as char).to_string().repeat(64),
    }
}

fn release_set() -> RuntimeReleaseSetManifestV1 {
    RuntimeReleaseSetManifestV1 {
        format_version: 1,
        release_set_id: "runtime-0.2.16".to_owned(),
        runtime_version: "0.2.16".to_owned(),
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        artifacts: vec![
            root_entry("linux", "x86_64", 'a'),
            root_entry("windows", "x86_64", 'd'),
            root_entry("macos", "aarch64", '7'),
            root_entry("android", "aarch64", '4'),
        ],
    }
}

#[test]
fn wire_enums_use_exact_snake_case_values_and_identity_rejects_generation_zero() {
    assert_eq!(
        serde_json::to_string(&RuntimeSlot::Latest).unwrap(),
        "\"latest\""
    );
    assert_eq!(
        serde_json::to_string(&RuntimeSlot::Stable).unwrap(),
        "\"stable\""
    );
    assert_eq!(
        serde_json::to_string(&RuntimeFileRole::SharedLibrary).unwrap(),
        "\"shared_library\""
    );

    let valid = RuntimeIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: "0.2.16".to_owned(),
        runtime_contract_version: 1,
        container_version: "0.2.16".to_owned(),
        session_generation: None,
    };
    assert_eq!(valid.validate(), Ok(()));
    assert_eq!(
        RuntimeIdentity {
            session_generation: Some(1),
            ..valid.clone()
        }
        .validate(),
        Ok(())
    );
    assert_eq!(
        RuntimeIdentity {
            session_generation: Some(0),
            ..valid
        }
        .validate(),
        Err(RuntimeManifestError::InvalidSessionGeneration)
    );
}

#[test]
fn identity_uses_the_panel_integer_boundaries() {
    let boundary = RuntimeIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: "0.2.16".to_owned(),
        runtime_contract_version: i32::MAX as u32,
        container_version: "0.2.16".to_owned(),
        session_generation: Some(i64::MAX as u64),
    };
    assert_eq!(boundary.validate(), Ok(()));
    assert_eq!(
        RuntimeIdentity {
            runtime_contract_version: i32::MAX as u32 + 1,
            ..boundary.clone()
        }
        .validate(),
        Err(RuntimeManifestError::InvalidField)
    );
    assert_eq!(
        RuntimeIdentity {
            session_generation: Some(i64::MAX as u64 + 1),
            ..boundary
        }
        .validate(),
        Err(RuntimeManifestError::InvalidSessionGeneration)
    );
}

#[test]
fn runtime_versions_match_the_panel_wire_syntax_and_sixty_four_byte_limit() {
    let valid_version = format!("1.2.3-{}", "a".repeat(58));
    assert_eq!(valid_version.len(), 64);
    let identity = RuntimeIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: valid_version,
        runtime_contract_version: 1,
        container_version: "0.2.16+build.7".to_owned(),
        session_generation: None,
    };
    assert_eq!(identity.validate(), Ok(()));

    for invalid_version in [
        "1.2",
        "v1.2.3",
        "1.2.3-alpha+build",
        "1.2.3-",
        &format!("1.2.3-{}", "a".repeat(59)),
    ] {
        let mut invalid = identity.clone();
        invalid.runtime_version = invalid_version.to_owned();
        assert_eq!(
            invalid.validate(),
            Err(RuntimeManifestError::InvalidField),
            "accepted {invalid_version:?}"
        );
    }

    let mut signed = container();
    signed.slots[0].manifest.runtime_version = "1.2.3-alpha+build".to_owned();
    assert_eq!(
        verify_container(&signed).unwrap_err(),
        RuntimeManifestError::InvalidField
    );
}

#[test]
fn signed_container_requires_one_latest_and_unique_slots() {
    let mut missing_latest = container();
    missing_latest.slots[0].slot = RuntimeSlot::Stable;
    assert_eq!(
        verify_container(&missing_latest).unwrap_err(),
        RuntimeManifestError::InvalidSlots
    );

    let mut duplicate = container();
    duplicate.slots.push(duplicate.slots[0].clone());
    assert_eq!(
        verify_container(&duplicate).unwrap_err(),
        RuntimeManifestError::InvalidSlots
    );
}

#[test]
fn equal_stable_is_packaging_evidence_but_not_selectable() {
    let mut manifest = container();
    manifest.slots.push(RuntimeSlotManifestV1 {
        slot: RuntimeSlot::Stable,
        manifest: artifact("0.2.16", "linux", "x86_64"),
    });
    let verified = verify_container(&manifest).unwrap();
    assert_eq!(verified.latest().runtime_version, "0.2.16");
    assert!(verified.stable().is_none());
    assert_eq!(
        verified.identity(RuntimeSlot::Latest, None).unwrap(),
        RuntimeIdentity {
            slot: RuntimeSlot::Latest,
            runtime_version: "0.2.16".to_owned(),
            runtime_contract_version: 1,
            container_version: "0.2.16".to_owned(),
            session_generation: None,
        }
    );
    assert_eq!(
        verified.identity(RuntimeSlot::Stable, None).unwrap_err(),
        RuntimeManifestError::InvalidSlots
    );

    manifest.stable_release_set_sha256 = Some("b".repeat(64));
    manifest.stable_platform_manifest_sha256 = Some("c".repeat(64));
    assert_eq!(
        verify_container(&manifest).unwrap_err(),
        RuntimeManifestError::InvalidStableDigests
    );
}

#[test]
fn distinct_stable_requires_a_complete_digest_pair() {
    let mut manifest = container();
    manifest.slots.push(RuntimeSlotManifestV1 {
        slot: RuntimeSlot::Stable,
        manifest: artifact("0.2.15", "linux", "x86_64"),
    });
    assert_eq!(
        verify_container(&manifest).unwrap_err(),
        RuntimeManifestError::InvalidStableDigests
    );

    manifest.stable_release_set_sha256 = Some("b".repeat(64));
    assert_eq!(
        verify_container(&manifest).unwrap_err(),
        RuntimeManifestError::InvalidStableDigests
    );

    manifest.stable_platform_manifest_sha256 = Some("c".repeat(64));
    let verified = verify_container(&manifest).unwrap();
    assert_eq!(verified.stable().unwrap().runtime_version, "0.2.15");
}

#[test]
fn target_and_compiled_contract_checks_fail_closed_with_inclusive_boundaries() {
    let manifest = container();
    assert!(verify_container(&manifest).is_ok());
    let bytes = canonical(&manifest);
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_container_manifest(&bytes, &signature, &public_key(), "windows", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::WrongTarget
    );
    assert_eq!(
        verify_container_manifest(&bytes, &signature, &public_key(), "linux", "aarch64")
            .unwrap_err(),
        RuntimeManifestError::WrongTarget
    );

    let mut too_new = container();
    too_new.minimum_runtime_contract = 2;
    too_new.maximum_runtime_contract = 2;
    too_new.slots[0].manifest.contract_version = 2;
    assert_eq!(
        verify_container(&too_new).unwrap_err(),
        RuntimeManifestError::UnsupportedContract
    );

    let mut invalid_range = container();
    invalid_range.minimum_runtime_contract = 2;
    invalid_range.maximum_runtime_contract = 1;
    assert_eq!(
        verify_container(&invalid_range).unwrap_err(),
        RuntimeManifestError::InvalidContractRange
    );
}

#[test]
fn signed_artifact_rejects_unsafe_portable_paths_and_aliases() {
    for bad_path in [
        "/absolute",
        "../parent",
        "bin/../agent",
        "./agent",
        "bin//agent",
        "bin\\agent",
        "C:/agent",
        "bin/agent:stream",
        "bin/NUL.txt",
        "bin/agent. ",
        "bin/control\u{7f}",
    ] {
        let mut manifest = artifact("0.2.16", "linux", "x86_64");
        manifest.files[0].path = bad_path.to_owned();
        let bytes = canonical(&manifest);
        let signature = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
        assert_eq!(
            verify_runtime_artifact_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
                .unwrap_err(),
            RuntimeManifestError::InvalidPath,
            "accepted {bad_path:?}"
        );
    }

    let mut aliases = artifact("0.2.16", "linux", "x86_64");
    aliases.files.push(file("BIN/NELOMAI-RUNTIME", 'b'));
    let bytes = canonical(&aliases);
    let signature = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_artifact_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::DuplicatePath
    );
}

#[test]
fn signed_artifact_rejects_malformed_sha256_and_duplicate_exact_paths() {
    let mut malformed = artifact("0.2.16", "linux", "x86_64");
    malformed.files[0].sha256 = "g".repeat(64);
    let bytes = canonical(&malformed);
    let signature = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_artifact_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::InvalidDigest
    );

    let mut duplicate = artifact("0.2.16", "linux", "x86_64");
    duplicate.files.push(file("bin/nelomai-runtime", 'b'));
    let bytes = canonical(&duplicate);
    let signature = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_artifact_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::DuplicatePath
    );
}

#[test]
fn signatures_are_strict_domain_separated_and_checked_before_json() {
    let manifest = container();
    let bytes = canonical(&manifest);
    let wrong_domain = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_container_manifest(&bytes, &wrong_domain, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::InvalidSignature
    );
    let malformed_json = b"not json";
    assert_eq!(
        verify_container_manifest(malformed_json, &[0; 64], &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::InvalidSignature
    );

    let artifact = artifact("0.2.16", "linux", "x86_64");
    let artifact_bytes = canonical(&artifact);
    let wrong_domain = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &artifact_bytes);
    assert_eq!(
        verify_runtime_artifact_manifest(
            &artifact_bytes,
            &wrong_domain,
            &public_key(),
            "linux",
            "x86_64"
        )
        .unwrap_err(),
        RuntimeManifestError::InvalidSignature
    );
}

#[test]
fn canonical_json_rejects_unknown_duplicate_and_whitespace_variants() {
    let manifest = container();
    let canonical_bytes = canonical(&manifest);
    let mut unknown: Value = serde_json::from_slice(&canonical_bytes).unwrap();
    unknown["unknown"] = json!(true);
    let unknown_bytes = serde_json::to_vec(&unknown).unwrap();
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &unknown_bytes);
    assert_eq!(
        verify_container_manifest(&unknown_bytes, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::InvalidJson
    );

    let duplicate_bytes = String::from_utf8(canonical_bytes.clone())
        .unwrap()
        .replacen("{", "{\"format_version\":1,", 1)
        .into_bytes();
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &duplicate_bytes);
    assert_eq!(
        verify_container_manifest(
            &duplicate_bytes,
            &signature,
            &public_key(),
            "linux",
            "x86_64"
        )
        .unwrap_err(),
        RuntimeManifestError::InvalidJson
    );

    let mut whitespace = canonical_bytes;
    whitespace.push(b'\n');
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &whitespace);
    assert_eq!(
        verify_container_manifest(&whitespace, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::NonCanonicalJson
    );
}

#[test]
fn unknown_manifest_versions_are_rejected_after_valid_signature() {
    let mut manifest = container();
    manifest.format_version = 2;
    let bytes = canonical(&manifest);
    let signature = sign(CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_container_manifest(&bytes, &signature, &public_key(), "linux", "x86_64")
            .unwrap_err(),
        RuntimeManifestError::UnsupportedFormatVersion
    );
}

#[test]
fn release_set_requires_exact_unique_targets_and_verifies_root_digest_and_domain() {
    let root = release_set();
    let bytes = canonical(&root);
    let signature = sign(RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN, &bytes);
    let expected_sha256 = "9d3ef5112944dd853918b388511fc4e541fdca78ec1ad0ee339cfa32b2299964";
    let verified =
        verify_runtime_release_set_manifest(&bytes, &signature, &public_key(), expected_sha256)
            .unwrap();
    assert_eq!(verified.sha256(), expected_sha256);
    assert_eq!(verified.manifest().artifacts.len(), 4);

    assert_eq!(
        verify_runtime_release_set_manifest(&bytes, &signature, &public_key(), &"0".repeat(64))
            .unwrap_err(),
        RuntimeManifestError::DigestMismatch
    );
    let wrong_domain = sign(RUNTIME_MANIFEST_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_release_set_manifest(&bytes, &wrong_domain, &public_key(), expected_sha256)
            .unwrap_err(),
        RuntimeManifestError::InvalidSignature
    );

    let mut duplicate = release_set();
    duplicate.artifacts[3] = duplicate.artifacts[2].clone();
    let duplicate_bytes = canonical(&duplicate);
    let signature = sign(RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN, &duplicate_bytes);
    assert_eq!(
        verify_runtime_release_set_manifest(
            &duplicate_bytes,
            &signature,
            &public_key(),
            &sha256_hex(&duplicate_bytes)
        )
        .unwrap_err(),
        RuntimeManifestError::InvalidReleaseSet
    );

    let mut incomplete = release_set();
    incomplete.artifacts.pop();
    let incomplete_bytes = canonical(&incomplete);
    let signature = sign(RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN, &incomplete_bytes);
    assert_eq!(
        verify_runtime_release_set_manifest(
            &incomplete_bytes,
            &signature,
            &public_key(),
            &sha256_hex(&incomplete_bytes)
        )
        .unwrap_err(),
        RuntimeManifestError::InvalidReleaseSet
    );
}

#[test]
fn release_set_schema_cannot_embed_its_own_root_hash() {
    let root = release_set();
    let mut value = serde_json::to_value(root).unwrap();
    value["stable_manifest_sha256"] = json!("a".repeat(64));
    let bytes = serde_json::to_vec(&value).unwrap();
    let signature = sign(RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_release_set_manifest(&bytes, &signature, &public_key(), &sha256_hex(&bytes))
            .unwrap_err(),
        RuntimeManifestError::InvalidJson
    );
}

#[test]
fn release_set_entries_require_every_exact_field() {
    let root = release_set();
    let mut value = serde_json::to_value(root).unwrap();
    value["artifacts"][0]
        .as_object_mut()
        .unwrap()
        .remove("archive_name");
    let bytes = serde_json::to_vec(&value).unwrap();
    let signature = sign(RUNTIME_RELEASE_SET_SIGNATURE_DOMAIN, &bytes);
    assert_eq!(
        verify_runtime_release_set_manifest(&bytes, &signature, &public_key(), &sha256_hex(&bytes))
            .unwrap_err(),
        RuntimeManifestError::InvalidJson
    );
}

#[test]
fn verifier_bounds_untrusted_input_before_parsing() {
    let bytes = vec![b' '; 1_048_577];
    assert_eq!(
        verify_container_manifest(&bytes, &[0; 64], &public_key(), "linux", "x86_64").unwrap_err(),
        RuntimeManifestError::InputTooLarge
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
