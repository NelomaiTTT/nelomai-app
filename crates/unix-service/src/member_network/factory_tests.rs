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

#[test]
fn a_new_boot_retires_only_ephemeral_authority_without_opening_native_members() {
    use nelomai_client_tunnel::redundancy::network::*;
    struct NoNative;
    impl NetworkSystem for NoNative {
        fn read(&mut self, _: &ResourceKey) -> std::io::Result<Option<NetworkValue>> {
            panic!("no native read across boots")
        }
        fn compare_exchange(
            &mut self,
            _: &ResourceKey,
            _: Option<&NetworkValue>,
            _: Option<&NetworkValue>,
        ) -> std::io::Result<()> {
            panic!("no native write across boots")
        }
    }
    let dir = root();
    let uid = unsafe { libc::geteuid() };
    let mut saved = SessionDirectory::open(dir.path(), scope(), "boot-one", uid).unwrap();
    let journal:NetworkJournal=serde_json::from_value(serde_json::json!({
        "owned":[{"original":null,"current":{"Route":{"destination":"0.0.0.0/1","scope":"Global","interface":42,"gateway":null,"metric":0}}}],
        "active":"A","pending":null,"stopping":false
    })).unwrap();
    saved.network.save(&journal).unwrap();
    fs::write(dir.path().join("slot-a/interface-name"), "utun42").unwrap();
    assert!(
        !super::factory::cleanup_previous_boot(dir.path(), scope(), "boot-one", uid, NoNative)
            .unwrap()
    );
    assert!(
        super::factory::cleanup_previous_boot(dir.path(), scope(), "boot-two", uid, NoNative)
            .unwrap()
    );
    assert!(
        super::factory::cleanup_previous_boot(dir.path(), scope(), "boot-two", uid, NoNative)
            .unwrap()
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("slot-a/interface-name")).unwrap(),
        "utun42"
    );
    assert!(super::factory::cleanup_previous_boot(dir.path(), scope(), "", uid, NoNative).is_err());
    assert!(
        SessionDirectory::open(dir.path(), scope(), "boot-two", uid).is_err(),
        "reboot grants cleanup only, never old Start"
    );
}

#[test]
fn reboot_during_bootstrap_requires_empty_private_slots_before_retirement() {
    use nelomai_client_tunnel::redundancy::network::*;
    struct NoNative;
    impl NetworkSystem for NoNative {
        fn read(&mut self, _: &ResourceKey) -> std::io::Result<Option<NetworkValue>> {
            panic!("bootstrap never owns native resources")
        }
        fn compare_exchange(
            &mut self,
            _: &ResourceKey,
            _: Option<&NetworkValue>,
            _: Option<&NetworkValue>,
        ) -> std::io::Result<()> {
            panic!("bootstrap never owns native resources")
        }
    }
    let uid = unsafe { libc::geteuid() };
    for populated in [false, true] {
        let dir = root();
        SessionDirectory::open(dir.path(), scope(), "boot-one", uid).unwrap();
        // Simulate a crash after the seal/slot directories, before the initial
        // empty network journal. No member may start before that write.
        fs::remove_file(dir.path().join("redundant-network.json")).unwrap();
        if populated {
            fs::write(dir.path().join("slot-a/owner"), b"retained").unwrap();
        }
        let result =
            super::factory::cleanup_previous_boot(dir.path(), scope(), "boot-two", uid, NoNative);
        assert_eq!(result.is_ok(), !populated);
        if populated {
            assert_eq!(
                fs::read(dir.path().join("slot-a/owner")).unwrap(),
                b"retained"
            );
        } else {
            assert!(result.unwrap());
            assert!(dir.path().join("redundant-session.json").exists());
        }
    }
}
