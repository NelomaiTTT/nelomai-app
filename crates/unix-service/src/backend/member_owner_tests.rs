use super::macos_launch::tests::{receipt, verified};
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
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
    let mut recovered = store(dir.path());
    assert!(recovered
        .begin(receipt(MemberTransport::WireGuard))
        .is_err());
    assert!(recovered.owned(&identity()).is_err());
    assert!(recovered.finish_stop().is_err());
}

#[test]
fn persisted_identity_is_scoped_private_and_only_exact_live_resource_is_recovered() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(receipt(MemberTransport::AmneziaWg3)).unwrap();
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
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
    owner.capture(identity()).unwrap();
    owner.begin_stop().unwrap();
    let mut recovered = store(dir.path());
    assert!(recovered.stopping());
    assert!(recovered
        .begin(receipt(MemberTransport::WireGuard))
        .is_err());
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
    closed.begin(receipt(MemberTransport::WireGuard)).unwrap();
    assert!(closed.owned(&identity()).is_err());
}

#[test]
fn live_owner_rejects_duplicate_start_before_native_cleanup() {
    let dir = directory();
    let mut owner = store(dir.path());
    assert!(owner.ensure_fresh().is_ok());
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
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
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
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
    assert!(owner.begin(receipt(MemberTransport::WireGuard)).is_err());
}

#[test]
fn restart_inspects_exact_saved_identity_without_touching_other_boot_or_unproven_launch() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
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
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
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
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
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

#[test]
fn failed_first_capture_keeps_cleanup_only_identity_in_memory() {
    let dir = directory();
    let mut owner = store(dir.path());
    owner.begin(receipt(MemberTransport::WireGuard)).unwrap();
    let state = dir.path().join("redundant-member.json");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(owner.capture_proven(verified(), false).is_err());
    assert_eq!(owner.identity(), Some(&identity()));
    assert!(owner.stopping());
    assert!(owner.ensure_fresh().is_err());
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
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    // Disk still has only the original receipt, not invented ownership.
    assert!(store(dir.path()).interrupted_launch());
}

#[test]
fn interrupted_receipt_requires_matching_kernel_proof_and_is_cleanup_only() {
    let dir = directory();
    let mut owner = store(dir.path());
    let expected = receipt(MemberTransport::WireGuard);
    owner.begin(expected.clone()).unwrap();
    drop(owner); // crash after spawn, before capture
    let mut recovered = store(dir.path());
    assert_eq!(recovered.receipt(), Some(&expected));
    assert!(recovered.identity().is_none());
    recovered.capture_proven(verified(), true).unwrap();
    let recovered = store(dir.path());
    assert!(recovered.stopping());
    assert_eq!(recovered.identity(), Some(&identity()));
    assert!(recovered.ensure_fresh().is_err());
}

#[test]
fn launch_proof_from_another_receipt_cannot_capture() {
    let dir = directory();
    let mut owner = store(dir.path());
    let mut other = receipt(MemberTransport::WireGuard);
    other.launch_nonce.replace_range(35..36, "2");
    owner.begin(other.clone()).unwrap();
    assert!(owner.capture_proven(verified(), true).is_err());
    assert_eq!(store(dir.path()).receipt(), Some(&other));
    assert!(owner.identity().is_none());
}

#[test]
fn malformed_receipt_never_written() {
    let dir = directory();
    let mut owner = store(dir.path());
    let mut bad = receipt(MemberTransport::WireGuard);
    bad.launch_nonce = "not-a-nonce".into();
    assert!(owner.begin(bad).is_err());
    assert!(!owner.cleanup_pending());
    assert!(std::fs::read(dir.path().join("redundant-member.json")).is_err());
}

const OLD_BOOT: &str = "72cc17e2-0000-4000-8000-000000000011";
const NEW_BOOT: &str = "72cc17e2-0000-4000-8000-000000000012";

fn reboot_receipt() -> super::macos_launch::LaunchReceipt {
    let mut r = receipt(MemberTransport::WireGuard);
    r.boot = OLD_BOOT.into();
    r
}

#[test]
fn changed_boot_retires_starting_durably_without_old_resource_inspection_or_removal() {
    let dir = directory();
    store(dir.path()).begin(reboot_receipt()).unwrap();
    let mut owner = store(dir.path());
    assert!(owner.retire_starting_after_boot(NEW_BOOT).unwrap());
    let mut reloaded = store(dir.path());
    assert!(!reloaded.interrupted_launch());
    assert!(!reloaded.cleanup_pending());
    assert!(reloaded.stopping()); // durable Closed, not active-role adoption
    assert!(reloaded.identity().is_none());
    assert_eq!(
        reloaded
            .recover(NEW_BOOT, |_| panic!("old resource lookup"))
            .unwrap(),
        None
    );
    reloaded
        .stop_owned(
            NEW_BOOT,
            |_| panic!("old resource lookup"),
            |_| panic!("old resource removal"),
        )
        .unwrap();
    assert!(!reloaded.retire_starting_after_boot(NEW_BOOT).unwrap());
}

#[test]
fn retirement_never_forgets_same_boot_or_malformed_boot() {
    let dir = directory();
    let mut owner = store(dir.path());
    let receipt = reboot_receipt();
    owner.begin(receipt.clone()).unwrap();
    assert!(!owner.retire_starting_after_boot(OLD_BOOT).unwrap());
    assert!(!owner
        .retire_starting_after_boot(&OLD_BOOT.to_ascii_uppercase())
        .unwrap());
    for bad in [
        "",
        " ",
        "boot-two",
        "00000000-0000-0000-0000-000000000000",
        "72cc17e2_0000-4000-8000-000000000012",
        "72cc17e2-0000-4000-8000-00000000001z",
        "72cc17e2-0000-4000-8000-000000000012\n",
    ] {
        assert!(owner.retire_starting_after_boot(bad).is_err());
        assert_eq!(owner.receipt(), Some(&receipt));
        assert_eq!(store(dir.path()).receipt(), Some(&receipt));
    }
    assert!(owner.ensure_fresh().is_err());
    assert!(owner.finish_stop().is_err());
}

#[test]
fn retirement_affects_only_starting_not_owned_or_empty() {
    let dir = directory();
    let mut owner = store(dir.path());
    assert!(!owner.retire_starting_after_boot(NEW_BOOT).unwrap());
    assert!(!dir.path().join("redundant-member.json").exists());
    owner.begin(reboot_receipt()).unwrap();
    let mut live = identity();
    live.boot = OLD_BOOT.into();
    owner.capture(live.clone()).unwrap();
    assert!(!owner.retire_starting_after_boot(NEW_BOOT).unwrap());
    assert_eq!(owner.identity(), Some(&live));
    assert!(!owner.stopping());
    owner.begin_stop().unwrap();
    assert!(!owner.retire_starting_after_boot(NEW_BOOT).unwrap());
    assert_eq!(store(dir.path()).identity(), Some(&live));
}

#[test]
fn retirement_write_failure_retains_starting_authority_and_can_retry() {
    let dir = directory();
    let mut owner = store(dir.path());
    let receipt = reboot_receipt();
    owner.begin(receipt.clone()).unwrap();
    let path = dir.path().join("redundant-member.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(owner.retire_starting_after_boot(NEW_BOOT).is_err());
    assert_eq!(owner.receipt(), Some(&receipt));
    assert!(owner.ensure_fresh().is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store(dir.path()).receipt(), Some(&receipt));
    assert!(owner.retire_starting_after_boot(NEW_BOOT).unwrap());
    assert!(!store(dir.path()).cleanup_pending());
}

#[test]
fn malformed_saved_boot_is_not_reboot_evidence() {
    let dir = directory();
    let mut owner = store(dir.path());
    let receipt = receipt(MemberTransport::WireGuard); // legacy fake "boot-one"
    owner.begin(receipt.clone()).unwrap();
    assert!(owner.retire_starting_after_boot(NEW_BOOT).is_err());
    assert_eq!(store(dir.path()).receipt(), Some(&receipt));
}

#[test]
fn live_attempt_no_child_closes_exact_receipt_and_allows_retry() {
    use super::macos_launch::tests::{fake_command, LaunchCase};
    for case in [LaunchCase::PrepareError, LaunchCase::SpawnError] {
        let dir = directory();
        let mut owner = store(dir.path());
        let receipt = reboot_receipt();
        assert!(owner
            .launch_attempt(receipt.clone(), |r| {
                assert_eq!(store(dir.path()).receipt(), Some(r)); // journal BEFORE effects
                fake_command(case)
            })
            .unwrap()
            .is_err());
        assert!(!owner.cleanup_pending());
        assert!(!store(dir.path()).cleanup_pending());
        assert!(owner.stopping());
        owner
            .launch_attempt(receipt, |_| fake_command(LaunchCase::Success))
            .unwrap()
            .unwrap();
        assert!(owner.interrupted_launch()); // success is NOT a capture
    }
}

#[test]
fn live_attempt_spawned_failures_and_recovery_never_grant_no_child_retirement() {
    use super::macos_launch::tests::{fake_command, LaunchCase};
    for case in [
        LaunchCase::Nonzero,
        LaunchCase::Timeout,
        LaunchCase::WaitError,
        LaunchCase::GuardianError,
    ] {
        let dir = directory();
        let mut owner = store(dir.path());
        let receipt = reboot_receipt();
        assert!(owner
            .launch_attempt(receipt.clone(), |_| fake_command(case))
            .unwrap()
            .is_err());
        assert_eq!(owner.receipt(), Some(&receipt));
        assert_eq!(store(dir.path()).receipt(), Some(&receipt));
        assert!(owner
            .launch_attempt::<(), std::io::Error>(receipt.clone(), |_| panic!("duplicate launch"))
            .is_err());
        assert!(store(dir.path())
            .launch_attempt::<(), std::io::Error>(receipt, |_| panic!(
                "crash recovery is not a fresh attempt"
            ))
            .is_err());
    }
}

#[test]
fn live_attempt_no_child_journal_failure_retains_authority() {
    use super::macos_launch::tests::{fake_command, LaunchCase};
    let dir = directory();
    let mut owner = store(dir.path());
    let receipt = reboot_receipt();
    let path = dir.path().join("redundant-member.json");
    assert!(owner
        .launch_attempt(receipt.clone(), |_| {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            fake_command(LaunchCase::SpawnError)
        })
        .is_err());
    assert_eq!(owner.receipt(), Some(&receipt));
    assert!(owner.ensure_fresh().is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(store(dir.path()).receipt(), Some(&receipt));
}

#[test]
fn live_attempt_no_child_rejects_replaced_durable_receipt() {
    use super::macos_launch::tests::{fake_command, LaunchCase};
    let dir = directory();
    let mut owner = store(dir.path());
    let receipt = reboot_receipt();
    let mut replacement = receipt.clone();
    replacement.boot = NEW_BOOT.into();
    replacement.launch_nonce.replace_range(35..36, "2");
    assert!(owner
        .launch_attempt(receipt.clone(), |_| {
            let mut other = store(dir.path());
            other.retire_starting_after_boot(NEW_BOOT).unwrap();
            other.begin(replacement.clone()).unwrap();
            fake_command(LaunchCase::SpawnError)
        })
        .is_err());
    assert_eq!(owner.receipt(), Some(&receipt));
    assert_eq!(store(dir.path()).receipt(), Some(&replacement));
}
