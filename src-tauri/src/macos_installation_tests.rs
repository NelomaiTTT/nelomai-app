use super::{macos_installation_action, macos_installer_command, InstallationAction};
use std::{path::Path, process::Command};

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
                "0.4.0", Some(installed), true,
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
            "0.4.0",
            Some("0.4.0"),
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
            "0.4.0",
            Some("0.4.0"),
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
                "0.4.0",
                Some("0.4.0"),
                true,
                Path::new("/Applications/Nelomai.app/Contents/MacOS/nelomai-app"),
                &bundle,
            )
            .unwrap(),
            InstallationAction::LaunchInstalled,
        );
    }
}
