use super::*;
use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::{
    dispatcher::digest, verify_container_manifest, RuntimeSlot, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};

fn signed(role: &str, path: &str, size: u64) -> (VerifiedContainerManifest, EngineIdentity) {
    let key = SigningKey::from_bytes(&[17; 32]); // test key only
    let value = serde_json::json!({
        "format_version":1,"container_version":"0.3.3","release_set_id":"a".repeat(64),
        "minimum_runtime_contract":1,"maximum_runtime_contract":1,
        "slots":[{"slot":"latest","manifest":{
            "format_version":1,"runtime_version":"0.3.3","source_commit":"b".repeat(40),
            "platform":"windows","architecture":"x86_64","contract_version":1,
            "files":[{"path":path,"role":role,"size_bytes":size,"sha256":"c".repeat(64)}]
        }}]
    });
    let bytes = serde_json::to_vec(&value).unwrap();
    let message = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, &bytes].concat();
    let verified = verify_container_manifest(
        &bytes,
        &key.sign(&message).to_bytes(),
        &key.verifying_key().to_bytes(),
        "windows",
        "x86_64",
    )
    .unwrap();
    let id = EngineIdentity {
        slot: RuntimeSlot::Latest,
        runtime_version: "0.3.3".into(),
        runtime_contract_version: 1,
        container_version: "0.3.3".into(),
        manifest_sha256: digest(&bytes),
    };
    (verified, id)
}

#[test]
fn dll_source_selection_requires_the_actual_signed_runtime_identity() {
    let (manifest, id) = signed("shared_library", "wintun.dll", 424448);
    let entry = wintun_entry(&manifest, &id.manifest_sha256, &id).unwrap();
    assert_eq!(entry.path, "wintun.dll");
    assert_eq!(entry.size_bytes, 424448);
    assert_eq!(entry.sha256, "c".repeat(64));
    for mutation in 0..5 {
        let mut other = id.clone();
        match mutation {
            0 => other.slot = RuntimeSlot::Stable,
            1 => other.runtime_version = "0.3.2".into(),
            2 => other.runtime_contract_version = 2,
            3 => other.container_version = "0.3.4".into(),
            _ => other.manifest_sha256 = "d".repeat(64),
        }
        assert!(wintun_entry(&manifest, &id.manifest_sha256, &other).is_err());
    }
}

#[test]
fn dll_source_never_falls_back_to_wrong_role_nested_path_or_unbounded_payload() {
    for (role, path, size) in [
        ("resource", "wintun.dll", 424448),
        ("shared_library", "other.dll", 424448),
        ("shared_library", "subdir/wintun.dll", 424448),
        ("shared_library", "wintun.dll", 16 * 1024 * 1024 + 1),
    ] {
        let (manifest, id) = signed(role, path, size);
        assert!(wintun_entry(&manifest, &id.manifest_sha256, &id).is_err());
    }
}
