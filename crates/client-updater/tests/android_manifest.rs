use nelomai_client_updater::{AndroidManifestError, AndroidUpdateManifest, UpdateEndpointPolicy};

fn manifest() -> AndroidUpdateManifest {
    AndroidUpdateManifest {
        version: "0.2.0".to_string(),
        url: "https://nelomai.ru/api/client/v1/updates/artifacts/update.apk".to_string(),
        signature: "a".repeat(64),
        sha256: "b".repeat(64),
        size_bytes: 42_000_000,
    }
}

#[test]
fn validates_private_android_artifact_metadata() {
    let policy = UpdateEndpointPolicy::new("https://nelomai.ru").unwrap();

    let validated = manifest().validate("0.2.0", &policy).unwrap();

    assert_eq!(validated.version, "0.2.0");
    assert_eq!(validated.signer_sha256, "a".repeat(64));
    assert_eq!(validated.sha256, "b".repeat(64));
    assert_eq!(validated.size_bytes, 42_000_000);
}

#[test]
fn rejects_untrusted_or_inconsistent_android_artifacts() {
    let policy = UpdateEndpointPolicy::new("https://nelomai.ru").unwrap();
    let mut external = manifest();
    external.url = "https://example.com/update.apk".to_string();
    assert_eq!(
        external.validate("0.2.0", &policy).unwrap_err(),
        AndroidManifestError::UntrustedArtifact
    );

    let mut wrong_version = manifest();
    wrong_version.version = "0.3.0".to_string();
    assert_eq!(
        wrong_version.validate("0.2.0", &policy).unwrap_err(),
        AndroidManifestError::VersionChanged
    );

    let mut invalid_signer = manifest();
    invalid_signer.signature = "not-a-certificate".to_string();
    assert_eq!(
        invalid_signer.validate("0.2.0", &policy).unwrap_err(),
        AndroidManifestError::InvalidSigner
    );
}
