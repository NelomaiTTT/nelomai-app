use super::factory::SessionDirectory;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::RuntimeSlot;
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
};
fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 9,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 4,
    }
}
fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
#[test]
fn scope_and_boot_are_sealed_before_slot_directories_and_reopen_is_recovery_only() {
    let d = root();
    let uid = unsafe { libc::geteuid() };
    let first = SessionDirectory::open(d.path(), scope(), "boot-one", uid).unwrap();
    assert!(!first.recovering);
    assert_eq!(
        serde_json::to_value(first.network.load().unwrap().unwrap()).unwrap(),
        serde_json::to_value(&first.journal).unwrap(),
    );
    for slot in ["slot-a", "slot-b"] {
        assert_eq!(
            fs::metadata(d.path().join(slot)).unwrap().mode() & 0o777,
            0o700
        );
    }
    assert!(
        SessionDirectory::open(d.path(), scope(), "boot-one", uid)
            .unwrap()
            .recovering
    );
    assert!(SessionDirectory::open(d.path(), scope(), "boot-two", uid).is_err());
    let mut other = scope();
    other.runtime = RuntimeSlot::Stable;
    assert!(SessionDirectory::open(d.path(), other, "boot-one", uid).is_err());
}
#[test]
fn unknown_contents_and_symlinked_slot_are_preserved_not_adopted() {
    let d = root();
    let uid = unsafe { libc::geteuid() };
    fs::write(d.path().join("user-file"), b"keep").unwrap();
    assert!(SessionDirectory::open(d.path(), scope(), "boot-one", uid).is_err());
    assert_eq!(fs::read(d.path().join("user-file")).unwrap(), b"keep");
    let d = root();
    SessionDirectory::open(d.path(), scope(), "boot-one", uid).unwrap();
    fs::rename(d.path().join("slot-b"), d.path().join("original-slot-b")).unwrap();
    symlink(d.path().join("original-slot-b"), d.path().join("slot-b")).unwrap();
    assert!(SessionDirectory::open(d.path(), scope(), "boot-one", uid).is_err());
    assert!(fs::symlink_metadata(d.path().join("slot-b"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn missing_network_journal_cannot_silently_forget_routes_of_previously_started_members() {
    let d = root();
    let uid = unsafe { libc::geteuid() };
    SessionDirectory::open(d.path(), scope(), "boot-one", uid).unwrap();
    fs::write(d.path().join("slot-a/interface-name"), "utun42").unwrap();
    fs::remove_file(d.path().join("redundant-network.json")).unwrap();
    assert!(SessionDirectory::open(d.path(), scope(), "boot-one", uid).is_err());
    assert_eq!(
        fs::read_to_string(d.path().join("slot-a/interface-name")).unwrap(),
        "utun42"
    );
}
