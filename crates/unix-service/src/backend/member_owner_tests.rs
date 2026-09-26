use super::member_owner::*;
use super::redundancy::SocketIdentity;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::TunnelSlot, RuntimeSlot};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 7,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 3,
    }
}
fn identity() -> UserspaceIdentity {
    UserspaceIdentity {
        boot: "boot-one".into(),
        interface: "utun42".into(),
        index: 42,
        socket: SocketIdentity {
            device: 1,
            inode: 2,
        },
    }
}
fn store(dir: &std::path::Path) -> MemberOwner {
    MemberOwner::open_for_owner(dir, scope(), TunnelSlot::A, unsafe { libc::geteuid() }).unwrap()
}
fn directory() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn interrupted_launch_has_no_adoption_authority_and_cannot_be_restarted() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    let mut recovered = store(dir.path());
    assert!(recovered.begin(MemberTransport::WireGuard).is_err());
    assert!(recovered.owned(&identity()).is_err());
    assert!(recovered.finish_stop().is_err());
}

#[test]
fn persisted_identity_is_scoped_private_and_only_exact_live_resource_is_recovered() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::AmneziaWg3).unwrap();
    owner.capture(identity()).unwrap();
    let recovered = store(dir.path());
    assert_eq!(recovered.scope, scope());
    assert_eq!(
        recovered.owned(&identity()).unwrap(),
        MemberTransport::AmneziaWg3
    );
    for mut replaced in [identity(), identity(), identity(), identity()]
        .into_iter()
        .enumerate()
    {
        match replaced.0 {
            0 => replaced.1.boot = "boot-two".into(),
            1 => replaced.1.index += 1,
            2 => replaced.1.socket.inode += 1,
            _ => replaced.1.interface = "utun43".into(),
        }
        assert!(recovered.owned(&replaced.1).is_err());
    }
    let uid = unsafe { libc::geteuid() };
    assert!(MemberOwner::open_for_owner(dir.path(), scope(), TunnelSlot::B, uid).is_err());
    let mut other = scope();
    other.connection_generation += 1;
    assert!(MemberOwner::open_for_owner(dir.path(), other, TunnelSlot::A, uid).is_err());
    assert_eq!(
        std::fs::metadata(dir.path().join("redundant-member.json"))
            .unwrap()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn stop_intent_survives_restart_and_replacement_waits_for_confirmed_cleanup() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    owner.capture(identity()).unwrap();
    owner.begin_stop().unwrap();
    let mut recovered = store(dir.path());
    assert!(recovered.stopping());
    assert!(recovered.begin(MemberTransport::WireGuard).is_err());
    assert_eq!(
        recovered.owned(&identity()).unwrap(),
        MemberTransport::WireGuard
    );
    recovered.finish_stop().unwrap();
    let mut closed = store(dir.path());
    assert!(closed.stopping());
    assert!(closed.identity().is_none());
    closed.finish_stop().unwrap();
    // SessionMembers owns the terminal whole-session fence. A cleaned reserve
    // slot can be reused inside a still-live session, with a new identity.
    closed.begin(MemberTransport::WireGuard).unwrap();
    assert!(closed.owned(&identity()).is_err());
}

#[test]
fn live_owner_rejects_duplicate_start_before_native_cleanup() {
    let dir = directory();
    let mut owner = store(dir.path());
    assert!(owner.ensure_fresh().is_ok());
    owner.begin(MemberTransport::WireGuard).unwrap();
    owner.capture(identity()).unwrap();
    assert!(owner.ensure_fresh().is_err());
    assert_eq!(
        owner.owned(&identity()).unwrap(),
        MemberTransport::WireGuard
    );
}

#[test]
fn failed_capture_or_stop_write_does_not_erase_proof_or_allow_new_launch() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    owner.capture(identity()).unwrap();
    std::fs::set_permissions(
        dir.path().join("redundant-member.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(owner.begin_stop().is_err());
    assert_eq!(
        owner.owned(&identity()).unwrap(),
        MemberTransport::WireGuard
    );
    assert!(owner.begin(MemberTransport::WireGuard).is_err());
}

#[test]
fn restart_inspects_exact_saved_identity_without_touching_other_boot_or_unproven_launch() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    assert!(owner
        .recover("boot-one", |_| panic!(
            "unproven launch must not be inspected as owned"
        ))
        .is_err());
    owner.capture(identity()).unwrap();
    assert_eq!(
        owner
            .recover("boot-two", |_| panic!(
                "stale boot must not inspect reused utun"
            ))
            .unwrap(),
        None
    );
    assert_eq!(
        owner
            .recover("boot-one", |saved| {
                assert_eq!(saved, &identity());
                Ok(Some(identity()))
            })
            .unwrap(),
        Some(MemberTransport::WireGuard)
    );
    let mut wrong = identity();
    wrong.socket.inode += 1;
    assert!(owner.recover("boot-one", |_| Ok(Some(wrong))).is_err());
    assert_eq!(owner.recover("boot-one", |_| Ok(None)).unwrap(), None);
}

#[test]
fn stop_verifies_native_removal_and_keeps_proof_if_command_only_claimed_success() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    owner.capture(identity()).unwrap();
    let live = std::cell::RefCell::new(Some(identity()));
    assert!(owner
        .stop_owned("boot-one", |_| Ok(live.borrow().clone()), |_| Ok(()))
        .is_err());
    assert!(store(dir.path()).stopping());
    assert!(store(dir.path()).identity().is_some());
    owner
        .stop_owned(
            "boot-one",
            |_| Ok(live.borrow().clone()),
            |_| {
                assert!(store(dir.path()).stopping());
                *live.borrow_mut() = None;
                Ok(())
            },
        )
        .unwrap();
    assert!(store(dir.path()).identity().is_none());
}

#[test]
fn disk_failure_does_not_leave_verified_native_vpn_running_on_stop() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(MemberTransport::WireGuard).unwrap();
    owner.capture(identity()).unwrap();
    let state = dir.path().join("redundant-member.json");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    let live = std::cell::RefCell::new(Some(identity()));
    assert!(owner
        .stop_owned(
            "boot-one",
            |_| Ok(live.borrow().clone()),
            |_| {
                *live.borrow_mut() = None;
                Ok(())
            }
        )
        .is_err());
    assert!(live.borrow().is_none());
    assert!(owner.cleanup_pending());
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    owner
        .stop_owned("boot-one", |_| Ok(None), |_| panic!("already gone"))
        .unwrap();
    assert!(!owner.cleanup_pending());
}
