use ed25519_dalek::{Signer, SigningKey};
use nelomai_client_container::InstalledRuntimeSelection;
use nelomai_contracts::{RuntimeSlot, CONTAINER_MANIFEST_SIGNATURE_DOMAIN};

#[test]
fn installed_selection_requires_manifest_trust_and_an_existing_preference() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selection.json");
    let bytes = include_bytes!("../../../contracts/fixtures/runtime/container-manifest-v1.json");
    let key = SigningKey::from_bytes(&[92; 32]);
    let mut signed = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    signed.extend_from_slice(bytes);
    std::fs::write(root.path().join("container-manifest-v1.json"), bytes).unwrap();
    std::fs::write(
        root.path().join("container-manifest-v1.sig"),
        key.sign(&signed).to_bytes(),
    )
    .unwrap();
    std::fs::write(
        &selected,
        br#"{"schema_version":1,"container_version":"0.2.16","selected_slot":"latest","pending_slot":null}"#,
    )
    .unwrap();
    let load = |key: Option<&[u8]>| {
        InstalledRuntimeSelection::load(root.path(), &selected, key, "linux", "x86_64")
    };
    assert!(load(None).is_err());
    assert!(load(Some(&[0; 32])).is_err());
    let verified = load(Some(&key.verifying_key().to_bytes())).unwrap();
    assert_eq!(verified.target().runtime_version, "0.2.16");
    assert_eq!(verified.target().runtime_slot, RuntimeSlot::Latest);
    std::fs::write(
        &selected,
        br#"{"schema_version":1,"container_version":"0.2.16","selected_slot":"stable","pending_slot":null}"#,
    )
    .unwrap();
    let recovered = load(Some(&key.verifying_key().to_bytes())).unwrap();
    assert_eq!(recovered.target().runtime_slot, RuntimeSlot::Latest);
    assert!(recovered.recovery().is_some());
    std::fs::remove_file(&selected).unwrap();
    assert!(load(Some(&key.verifying_key().to_bytes())).is_err());
}
