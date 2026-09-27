use super::*;
use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::CONTAINER_MANIFEST_SIGNATURE_DOMAIN;
use serde_json::json;
use std::fs;

// Real signed installation/marker/locks. The fake executable is data, never run.
fn fixture() -> (tempfile::TempDir, Installation, Vec<u8>) {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let engine = source.join("engines/latest/0.3.3/nelomai-windows-service.exe");
    fs::create_dir_all(engine.parent().unwrap()).unwrap();
    fs::write(&engine, b"fake-native-engine").unwrap();
    let key = SigningKey::from_bytes(&[81; 32]);
    let bytes = serde_json::to_vec(&json!({
        "format_version":1,"container_version":"0.3.3","release_set_id":"test-0.3.3",
        "minimum_runtime_contract":1,"maximum_runtime_contract":1,
        "slots":[{"slot":"latest","manifest":{
            "format_version":1,"runtime_version":"0.3.3",
            "source_commit":"0123456789abcdef0123456789abcdef01234567",
            "platform":"windows","architecture":"x86_64","contract_version":1,
            "files":[{"path":"nelomai-windows-service.exe","size_bytes":18,
                "sha256":d::digest(b"fake-native-engine"),"role":"executable"}]
        }}]
    }))
    .unwrap();
    let mut message = CONTAINER_MANIFEST_SIGNATURE_DOMAIN.to_vec();
    message.extend(&bytes);
    fs::write(source.join(d::MANIFEST_NAME), &bytes).unwrap();
    fs::write(
        source.join(d::SIGNATURE_NAME),
        key.sign(&message).to_bytes(),
    )
    .unwrap();
    let broker = temp.path().join("broker.exe");
    fs::write(&broker, b"broker").unwrap();
    #[cfg(unix)]
    let owner = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(&broker).unwrap().uid()
    };
    #[cfg(not(unix))]
    let owner = 0;
    let installation = Installation::for_owner(
        &temp.path().join("privileged"),
        key.verifying_key().to_bytes(),
        "windows",
        "x86_64",
        owner,
    );
    let layout = installation
        .install(&source, &broker, "S-1-5-21-1000", &d::RealInstallIo)
        .unwrap();
    let marker = serde_json::to_vec(&layout.identity).unwrap();
    d::write_new(&installation.root.join(d::ACTIVE_ENGINE_NAME), &marker).unwrap();
    (temp, installation, marker)
}

#[test]
fn stale_marker_retires_only_after_verified_owned_cleanup_under_both_locks() {
    let (_temp, installation, marker) = fixture();
    let path = installation.root.join(d::ACTIVE_ENGINE_NAME);
    let mut called = false;
    recover(&installation, |layout| {
        called = true;
        assert_eq!(layout.identity.runtime_version, "0.3.3");
        assert_eq!(fs::read(&path).unwrap(), marker);
        assert!(d::MutationGuard::acquire(&installation.root).is_err());
        assert!(d::MutationGuard::at(&installation.root.join("engine-owner.lock")).is_err());
        Ok(())
    })
    .unwrap();
    assert!(called);
    assert!(!path.exists());
}

#[test]
fn live_owner_or_dispatcher_mutation_fences_recovery_without_native_effects() {
    for name in ["engine-owner.lock", "mutation.lock"] {
        let (_temp, installation, bytes) = fixture();
        let _live = d::MutationGuard::at(&installation.root.join(name)).unwrap();
        assert!(recover(&installation, |_| panic!("live owner")).is_err());
        assert_eq!(
            fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
            bytes
        );
    }
}

#[test]
fn cleanup_failure_retains_exact_marker_and_prevents_publication() {
    let (_temp, installation, bytes) = fixture();
    let mut called = false;
    assert!(recover(&installation, |_| {
        called = true;
        Err(d::blocked())
    })
    .is_err());
    assert!(called);
    assert_eq!(
        fs::read(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap(),
        bytes
    );
}

#[test]
fn invalid_identity_signature_or_engine_never_reaches_cleanup() {
    for fault in ["identity", "signature", "engine", "corrupt"] {
        let (_temp, installation, _) = fixture();
        let layout = installation.load().unwrap();
        let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
        match fault {
            "identity" => {
                let mut wrong = layout.identity.clone();
                wrong.manifest_sha256 = "f".repeat(64);
                fs::write(&marker, serde_json::to_vec(&wrong).unwrap()).unwrap();
            }
            "signature" => fs::write(layout.directory.join(d::SIGNATURE_NAME), [0; 64]).unwrap(),
            "engine" => fs::write(layout.engine_path(), b"tampered").unwrap(),
            _ => fs::write(&marker, b"corrupt").unwrap(),
        }
        let before = fs::read(&marker).unwrap();
        assert!(recover(&installation, |_| panic!("unverified owner")).is_err());
        assert_eq!(fs::read(&marker).unwrap(), before);
    }
}

#[test]
fn changed_marker_is_not_retired_after_cleanup() {
    let (_temp, installation, _) = fixture();
    let marker = installation.root.join(d::ACTIVE_ENGINE_NAME);
    let mut called = false;
    assert!(recover(&installation, |_| {
        called = true;
        fs::write(&marker, b"different owner")?;
        Ok(())
    })
    .is_err());
    assert!(called);
    assert_eq!(fs::read(marker).unwrap(), b"different owner");
}

#[test]
fn missing_marker_has_no_native_effects() {
    let (_temp, installation, _) = fixture();
    fs::remove_file(installation.root.join(d::ACTIVE_ENGINE_NAME)).unwrap();
    recover(&installation, |_| panic!("nothing to recover")).unwrap();
}
