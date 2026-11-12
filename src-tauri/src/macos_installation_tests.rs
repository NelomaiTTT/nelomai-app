use super::{macos_installation_action, macos_installer_command, InstallationAction};
use ed25519_dalek::{Signer, SigningKey};
use nelomai_contracts::{
    verify_container_manifest, VerifiedContainerManifest, CONTAINER_MANIFEST_SIGNATURE_DOMAIN,
};
use std::{path::Path, process::Command};

#[test]
fn pre_auth_installer_distinguishes_cancellation_from_shell_failure() {
    let long_cancel = format!("error \"{}\" number -128", "cancel ".repeat(256));
    for (script, expected) in [
        ("error number -128", Some(false)),
        (&long_cancel, Some(false)),
        (r#"do shell script "/bin/sh -c 'exit 17'""#, None),
        (r#"error "synthetic text (-128)" number 17"#, None),
        (r#"do shell script "/usr/bin/true""#, Some(true)),
    ] {
        let mut command = Command::new("/usr/bin/osascript");
        command.args(["-e", script]);
        let result = super::run_macos_pre_auth_installer(&mut command);
        match expected {
            Some(outcome) => assert_eq!(result.unwrap(), outcome),
            None => assert_eq!(
                result.unwrap_err().to_string(),
                "common installation failed"
            ),
        }
    }
}

fn manifest_value(version: &str) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../contracts/fixtures/runtime/container-manifest-v1.json"
    ))
    .unwrap();
    value["container_version"] = version.into();
    value["slots"][0]["manifest"]["runtime_version"] = version.into();
    value["slots"][0]["manifest"]["platform"] = "macos".into();
    value["slots"][0]["manifest"]["architecture"] = "aarch64".into();
    value
}

fn verify_fixture(value: &serde_json::Value) -> VerifiedContainerManifest {
    let bytes = serde_json::to_vec(value).unwrap();
    let key = SigningKey::from_bytes(&[49; 32]);
    let signed = [CONTAINER_MANIFEST_SIGNATURE_DOMAIN, bytes.as_slice()].concat();
    verify_container_manifest(
        &bytes,
        &key.sign(&signed).to_bytes(),
        &key.verifying_key().to_bytes(),
        "macos",
        "aarch64",
    )
    .unwrap()
}

fn manifest(version: &str) -> VerifiedContainerManifest {
    verify_fixture(&manifest_value(version))
}

fn set_quarantine(bundle: &Path) {
    assert!(Command::new("/usr/bin/xattr")
        .args(["-w", "com.apple.quarantine", "00c1;6ae7b1f3;Telegram;"])
        .arg(bundle)
        .status()
        .unwrap()
        .success());
}

#[test]
fn downloaded_installation_is_repaired_before_another_translocated_handoff() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    set_quarantine(&bundle);
    for installed in ["0.4.0", "0.4.1"] {
        assert_eq!(
            macos_installation_action(
                &manifest("0.4.0"), Some(&manifest(installed)), true,
                Path::new("/private/var/folders/test/AppTranslocation/fixture/d/Nelomai.app/Contents/MacOS/nelomai-app"),
                &bundle,
            ).unwrap(),
            InstallationAction::RepairDownloadMetadata,
        );
    }
}

#[test]
fn protected_metadata_repair_uses_explicit_nonreplacing_installer_mode() {
    let source = Path::new("/Applications/candidate's Nelomai.app");
    let installed = Path::new("/Library/Application Support/Nelomai/common/Nelomai.app");
    let command = macos_installer_command(
        InstallationAction::RepairDownloadMetadata,
        source,
        installed,
        501,
    );
    assert_eq!(command.get_program(), "/usr/bin/osascript");
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        vec![
            source
                .join("Contents/Resources/install-common-macos.applescript")
                .into_os_string(),
            source
                .join("Contents/Resources/install-common-macos.sh")
                .into_os_string(),
            "501".into(),
            installed.as_os_str().to_owned(),
            "--repair-download-metadata".into(),
        ]
    );
}

#[test]
fn already_admitted_exact_path_owner_continues_without_reopening_itself() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    set_quarantine(&bundle);
    assert_eq!(
        macos_installation_action(
            &manifest("0.4.0"),
            Some(&manifest("0.4.0")),
            true,
            &bundle.join("Contents/MacOS/nelomai-app"),
            &bundle,
        )
        .unwrap(),
        InstallationAction::Continue,
    );
    // Matching the path alone must not replace the existing ownership checks.
    assert_eq!(
        macos_installation_action(
            &manifest("0.4.0"),
            Some(&manifest("0.4.0")),
            false,
            &bundle.join("Contents/MacOS/nelomai-app"),
            &bundle,
        )
        .unwrap(),
        InstallationAction::RepairInstalled,
    );
}

#[test]
fn normalized_relaunch_uses_installed_owner_without_another_repair() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    for _ in 0..2 {
        assert_eq!(
            macos_installation_action(
                &manifest("0.4.0"),
                Some(&manifest("0.4.0")),
                true,
                Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
                &bundle,
            )
            .unwrap(),
            InstallationAction::LaunchInstalled,
        );
    }
}

#[test]
fn different_same_version_candidate_is_installed_instead_of_reopening_previous_build() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    let installed = manifest("0.4.0");
    let mut value = manifest_value("0.4.0");
    value["slots"][0]["manifest"]["files"][0]["sha256"] = "b".repeat(64).into();
    let candidate = verify_fixture(&value);
    for protected in [true, false] {
        assert_eq!(macos_installation_action(
            &candidate, Some(&installed), protected,
            Path::new("/Volumes/Nelomai/Nelomai.app/Contents/MacOS/nelomai-app"), &bundle,
        ).unwrap(), InstallationAction::InstallCandidate,
        "a different authenticated build must not be discarded just because its version is equal");
    }
    set_quarantine(&bundle);
    assert_eq!(
        macos_installation_action(
            &candidate,
            Some(&installed),
            true,
            Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
            &bundle,
        )
        .unwrap(),
        InstallationAction::InstallCandidate,
        "metadata repair must not retain the different old build"
    );
}

#[test]
fn same_version_stable_payload_change_also_requires_installation() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    let mut old = manifest_value("0.4.0");
    let mut stable = old["slots"][0].clone();
    stable["slot"] = "stable".into();
    stable["manifest"]["runtime_version"] = "0.3.8".into();
    old["slots"].as_array_mut().unwrap().push(stable);
    old["stable_release_set_sha256"] = "c".repeat(64).into();
    old["stable_platform_manifest_sha256"] = "d".repeat(64).into();
    let installed = verify_fixture(&old);
    let mut new = old.clone();
    new["slots"][1]["manifest"]["runtime_version"] = "0.3.11".into();
    let candidate = verify_fixture(&new);
    assert_eq!(
        macos_installation_action(
            &candidate,
            Some(&installed),
            true,
            Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
            &bundle,
        )
        .unwrap(),
        InstallationAction::InstallCandidate
    );
}

#[test]
fn identical_manifest_is_idempotent_and_lower_version_never_replaces() {
    let temporary = tempfile::tempdir().unwrap();
    let bundle = temporary.path().join("Nelomai.app");
    std::fs::create_dir(&bundle).unwrap();
    let candidate = manifest("0.4.0");
    let identical = manifest("0.4.0");
    let newer = manifest("0.4.1");
    for installed in [&identical, &newer] {
        for _ in 0..2 {
            assert_eq!(
                macos_installation_action(
                    &candidate,
                    Some(installed),
                    true,
                    Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
                    &bundle,
                )
                .unwrap(),
                InstallationAction::LaunchInstalled
            );
        }
    }
    assert_eq!(
        macos_installation_action(
            &candidate,
            Some(&newer),
            false,
            Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
            &bundle,
        )
        .unwrap(),
        InstallationAction::RepairInstalled
    );
}
