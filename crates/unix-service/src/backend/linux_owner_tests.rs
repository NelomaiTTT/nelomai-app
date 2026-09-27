use super::linux_owner::*;
use super::redundancy::SocketIdentity;
use nelomai_client_tunnel::redundancy::SessionScope;
use nelomai_contracts::{dispatcher::TunnelSlot, RuntimeSlot};
use std::{
    cell::RefCell,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 7,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 3,
    }
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn kernel_creation_is_exclusive_with_alias_and_up_in_the_creation_request() {
    let command = kernel_create_command("/sbin/ip", "nlm-wga", "opaque-owner");
    let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
    assert_eq!(
        args,
        [
            "link",
            "add",
            "name",
            "nlm-wga",
            "alias",
            "opaque-owner",
            "up",
            "type",
            "wireguard"
        ]
    );
    // This tests only construction; executing native commands is forbidden.
}

#[test]
fn privileged_ip_requires_root_owned_regular_executable_without_shared_writes() {
    // Fake stat values exercise the policy without creating/executing a root binary.
    for (regular, uid, mode, expected) in [
        (true, 0, 0o100755, true),
        (true, 0, 0o100700, true),
        (true, 501, 0o100755, false),
        (true, 0, 0o100775, false),
        (true, 0, 0o100757, false),
        (true, 0, 0o100644, false),
        (false, 0, 0o120777, false), // symlink_metadata must reject a symlink
        (false, 0, 0o040755, false), // directory
    ] {
        assert_eq!(
            trusted_ip_file(regular, uid, mode),
            expected,
            "uid={uid} mode={mode:o}"
        );
    }
}
fn open(dir: &Path) -> LinuxOwner {
    LinuxOwner::open_for_owner(dir, scope(), TunnelSlot::A, unsafe { libc::geteuid() }).unwrap()
}
fn started(dir: &Path, transport: MemberTransport) -> (LinuxOwner, LinuxIdentity) {
    let mut owner = open(dir);
    let alias = owner.begin(transport, "boot-one").unwrap();
    let identity = LinuxIdentity {
        boot: "boot-one".into(),
        index: 42,
        interface: match transport {
            MemberTransport::WireGuard => "nlm-wga",
            MemberTransport::AmneziaWg3 => "nlm-awga",
        }
        .into(),
        proof: match transport {
            MemberTransport::WireGuard => NativeProof::Kernel { alias },
            MemberTransport::AmneziaWg3 => NativeProof::Userspace(SocketIdentity {
                device: 1,
                inode: 2,
            }),
        },
    };
    owner.capture(identity.clone()).unwrap();
    (owner, identity)
}

#[test]
fn begin_is_durable_and_reopened_launch_cannot_replay_or_capture() {
    let dir = directory();
    let mut owner = open(dir.path());
    let alias = owner.begin(MemberTransport::WireGuard, "boot-one").unwrap();
    let mut recovered = open(dir.path());
    assert!(recovered.cleanup_pending());
    assert_eq!(recovered.scope, scope());
    assert!(recovered
        .begin(MemberTransport::WireGuard, "boot-one")
        .is_err());
    assert!(recovered
        .capture(LinuxIdentity {
            boot: "boot-one".into(),
            interface: "nlm-wga".into(),
            index: 42,
            proof: NativeProof::Kernel { alias }
        })
        .is_err());
    assert!(recovered
        .stop_owned(
            "boot-one",
            |_| panic!("uncaptured launch cannot inspect"),
            |_| panic!("uncaptured launch cannot delete")
        )
        .is_err());
    assert!(open(dir.path()).cleanup_pending());
}

#[test]
fn launch_persists_intent_before_io_and_proof_before_returning_for_configuration() {
    let dir = directory();
    let mut owner = open(dir.path());
    owner
        .launch(MemberTransport::WireGuard, "boot-one", |alias| {
            let pending = open(dir.path());
            assert!(pending.cleanup_pending());
            assert!(pending.identity().is_none());
            Ok(LinuxIdentity {
                boot: "boot-one".into(),
                interface: "nlm-wga".into(),
                index: 42,
                proof: NativeProof::Kernel {
                    alias: alias.into(),
                },
            })
        })
        .unwrap();
    assert_eq!(open(dir.path()).identity(), owner.identity());
    assert!(owner.identity().is_some());
    assert!(open(dir.path())
        .launch(MemberTransport::WireGuard, "boot-one", |_| panic!(
            "restart must not launch"
        ))
        .is_err());
}

#[test]
fn failed_native_launch_retains_starting_and_never_captures_foreign_name() {
    let dir = directory();
    let mut owner = open(dir.path());
    assert!(owner
        .launch(MemberTransport::WireGuard, "boot-one", |_| Err(
            io::Error::other("already exists")
        ))
        .is_err());
    let recovered = open(dir.path());
    assert!(recovered.cleanup_pending());
    assert!(recovered.identity().is_none());
}

#[test]
fn persisted_proof_rejects_other_scopes_slots_and_replaced_native_identity() {
    for transport in [MemberTransport::WireGuard, MemberTransport::AmneziaWg3] {
        let dir = directory();
        let (_, identity) = started(dir.path(), transport);
        let owner = open(dir.path());
        assert_eq!(owner.owned(&identity).unwrap(), transport);
        let uid = unsafe { libc::geteuid() };
        assert!(LinuxOwner::open_for_owner(dir.path(), scope(), TunnelSlot::B, uid).is_err());
        for field in 0..4 {
            let mut other = scope();
            match field {
                0 => other.runtime = RuntimeSlot::Stable,
                1 => other.runtime_generation += 1,
                2 => other.connection_generation += 1,
                _ => other.session_id = "72cc17e2-0000-4000-8000-000000000002".into(),
            }
            assert!(LinuxOwner::open_for_owner(dir.path(), other, TunnelSlot::A, uid).is_err());
        }
        for field in 0..6 {
            let mut wrong = identity.clone();
            match field {
                0 => wrong.boot = "boot-two".into(),
                1 => wrong.index += 1,
                2 => wrong.interface = "nlm-wgb".into(),
                3 => match &mut wrong.proof {
                    NativeProof::Kernel { alias } => alias.push('x'),
                    NativeProof::Userspace(socket) => socket.inode += 1,
                },
                4 => match &mut wrong.proof {
                    NativeProof::Kernel { alias } => alias.clear(),
                    NativeProof::Userspace(socket) => socket.device += 1,
                },
                _ => {
                    wrong.proof = match transport {
                        MemberTransport::WireGuard => NativeProof::Userspace(SocketIdentity {
                            device: 1,
                            inode: 2,
                        }),
                        MemberTransport::AmneziaWg3 => NativeProof::Kernel {
                            alias: "foreign".into(),
                        },
                    }
                }
            }
            assert!(owner.owned(&wrong).is_err());
            let mut recovered = open(dir.path());
            assert!(recovered
                .stop_owned(
                    "boot-one",
                    |_| Ok(Some(wrong.clone())),
                    |_| panic!("foreign deletion")
                )
                .is_err());
            assert!(recovered.cleanup_pending());
        }
        assert_eq!(
            std::fs::metadata(dir.path().join("redundant-linux-member.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn capture_rejects_wrong_boot_name_transport_and_alias_without_losing_intent() {
    for field in 0..5 {
        let dir = directory();
        let mut owner = open(dir.path());
        let alias = owner.begin(MemberTransport::WireGuard, "boot-one").unwrap();
        let mut identity = LinuxIdentity {
            boot: "boot-one".into(),
            interface: "nlm-wga".into(),
            index: 42,
            proof: NativeProof::Kernel { alias },
        };
        match field {
            0 => identity.boot = "boot-two".into(),
            1 => identity.interface = "nlm-wgb".into(),
            2 => identity.index = 0,
            3 => {
                identity.proof = NativeProof::Kernel {
                    alias: "foreign".into(),
                }
            }
            _ => {
                identity.proof = NativeProof::Userspace(SocketIdentity {
                    device: 1,
                    inode: 2,
                })
            }
        }
        assert!(owner.capture(identity).is_err());
        assert!(open(dir.path()).cleanup_pending());
        assert!(owner.identity().is_none());
    }
}

#[test]
fn boot_change_closes_old_proof_without_inspecting_or_deleting_current_names() {
    let dir = directory();
    let (mut owner, _) = started(dir.path(), MemberTransport::WireGuard);
    owner
        .stop_owned(
            "boot-two",
            |_| panic!("new boot must not inspect old name"),
            |_| panic!("new boot must not delete"),
        )
        .unwrap();
    assert!(!open(dir.path()).cleanup_pending());
}

#[test]
fn stop_failure_retains_proof_and_durable_stop_intent_for_retry() {
    let dir = directory();
    let (mut owner, identity) = started(dir.path(), MemberTransport::WireGuard);
    assert!(owner
        .stop_owned(
            "boot-one",
            |_| Ok(Some(identity.clone())),
            |_| {
                assert!(open(dir.path()).stopping());
                Err(io::Error::other("injected delete failure"))
            }
        )
        .is_err());
    let mut recovered = open(dir.path());
    assert!(recovered.stopping());
    assert_eq!(recovered.identity(), Some(&identity));
    assert!(recovered
        .begin(MemberTransport::WireGuard, "boot-one")
        .is_err());
    let live = RefCell::new(Some(identity.clone()));
    recovered
        .stop_owned(
            "boot-one",
            |_| Ok(live.borrow().clone()),
            |saved| {
                assert_eq!(saved, &identity);
                *live.borrow_mut() = None;
                Ok(())
            },
        )
        .unwrap();
    assert!(!open(dir.path()).cleanup_pending());
}

#[test]
fn lost_cleanup_ack_is_resolved_as_absent_without_second_delete() {
    for transport in [MemberTransport::WireGuard, MemberTransport::AmneziaWg3] {
        let dir = directory();
        let (mut owner, identity) = started(dir.path(), transport);
        let live = RefCell::new(Some(identity));
        assert!(owner
            .stop_owned(
                "boot-one",
                |_| Ok(live.borrow().clone()),
                |_| {
                    *live.borrow_mut() = None;
                    Err(io::Error::other("lost ack"))
                }
            )
            .is_err());
        let mut recovered = open(dir.path());
        assert!(recovered.stopping());
        recovered
            .stop_owned("boot-one", |_| Ok(None), |_| panic!("already absent"))
            .unwrap();
        assert!(!open(dir.path()).cleanup_pending());
    }
}

#[test]
fn successful_delete_without_confirmed_absence_retains_proof() {
    let dir = directory();
    let (mut owner, identity) = started(dir.path(), MemberTransport::AmneziaWg3);
    assert!(owner
        .stop_owned("boot-one", |_| Ok(Some(identity.clone())), |_| Ok(()))
        .is_err());
    assert!(open(dir.path()).stopping());
    assert_eq!(open(dir.path()).identity(), Some(&identity));
}

#[test]
fn failed_capture_write_preserves_starting_and_stop_write_failure_preserves_proof() {
    let dir = directory();
    let (mut owner, identity) = started(dir.path(), MemberTransport::WireGuard);
    std::fs::set_permissions(
        dir.path().join("redundant-linux-member.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let live = RefCell::new(Some(identity.clone()));
    assert!(owner
        .stop_owned(
            "boot-one",
            |_| Ok(live.borrow().clone()),
            |saved| {
                assert_eq!(saved, &identity);
                *live.borrow_mut() = None;
                Ok(())
            }
        )
        .is_err());
    assert!(live.borrow().is_none());
    assert_eq!(owner.identity(), Some(&identity));
    assert!(owner.cleanup_pending());

    let dir = directory();
    let mut owner = open(dir.path());
    let alias = owner.begin(MemberTransport::WireGuard, "boot-one").unwrap();
    let path = dir.path().join("redundant-linux-member.json");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(owner
        .capture(LinuxIdentity {
            boot: "boot-one".into(),
            interface: "nlm-wga".into(),
            index: 42,
            proof: NativeProof::Kernel { alias }
        })
        .is_err());
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut recovered = open(dir.path());
    assert!(recovered.cleanup_pending());
    assert!(recovered.identity().is_none());
    assert!(recovered
        .stop_owned("boot-one", |_| panic!("no proof"), |_| panic!("no proof"))
        .is_err());
}

#[test]
fn unavailable_journal_root_still_stops_exact_member_but_retains_proof_and_error() {
    for transport in [MemberTransport::WireGuard, MemberTransport::AmneziaWg3] {
        let dir = directory();
        let root = dir.path().join("owner");
        let offline = dir.path().join("offline");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (mut owner, identity) = started(&root, transport);
        let original = std::fs::read(root.join("redundant-linux-member.json")).unwrap();
        std::fs::rename(&root, &offline).unwrap();
        let live = RefCell::new(Some(identity.clone()));
        let error = owner
            .stop_owned(
                "boot-one",
                |_| Ok(live.borrow().clone()),
                |saved| {
                    assert_eq!(saved, &identity);
                    *live.borrow_mut() = None;
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(
            live.borrow().is_none(),
            "disk failure must not leave the owned tunnel running"
        );
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(owner.identity(), Some(&identity));
        assert!(owner.cleanup_pending());
        assert!(owner.stopping());
        assert!(owner.ensure_fresh().is_err());
        assert_eq!(
            std::fs::read(offline.join("redundant-linux-member.json")).unwrap(),
            original
        );
        std::fs::rename(&offline, &root).unwrap();
        owner
            .stop_owned("boot-one", |_| Ok(None), |_| panic!("already removed"))
            .unwrap();
        assert!(!open(&root).cleanup_pending());
    }
}

#[test]
fn failed_stop_persistence_never_authorizes_deleting_replacement() {
    let dir = directory();
    let (mut owner, identity) = started(dir.path(), MemberTransport::WireGuard);
    let mut replacement = identity.clone();
    replacement.proof = NativeProof::Kernel {
        alias: "foreign".into(),
    };
    std::fs::set_permissions(
        dir.path().join("redundant-linux-member.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(owner
        .stop_owned(
            "boot-one",
            |_| Ok(Some(replacement.clone())),
            |_| panic!("foreign deletion")
        )
        .is_err());
    assert_eq!(owner.identity(), Some(&identity));
    assert!(owner.stopping());
    assert!(owner.cleanup_pending());
}

#[test]
fn failed_capture_keeps_live_proof_for_cleanup_but_restart_remains_starting() {
    for transport in [MemberTransport::WireGuard, MemberTransport::AmneziaWg3] {
        let dir = directory();
        let path = dir.path().join("redundant-linux-member.json");
        let mut owner = open(dir.path());
        let live = RefCell::new(None);
        assert!(owner
            .launch(transport, "boot-one", |alias| {
                let identity = LinuxIdentity {
                    boot: "boot-one".into(),
                    index: 42,
                    interface: match transport {
                        MemberTransport::WireGuard => "nlm-wga",
                        MemberTransport::AmneziaWg3 => "nlm-awga",
                    }
                    .into(),
                    proof: match transport {
                        MemberTransport::WireGuard => NativeProof::Kernel {
                            alias: alias.into(),
                        },
                        MemberTransport::AmneziaWg3 => NativeProof::Userspace(SocketIdentity {
                            device: 1,
                            inode: 2,
                        }),
                    },
                };
                *live.borrow_mut() = Some(identity.clone());
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
                Ok(identity)
            })
            .is_err());
        let identity = live.borrow().clone().unwrap();
        assert_eq!(
            owner.identity(),
            Some(&identity),
            "failed capture write must retain exact live proof"
        );
        assert!(
            owner.stopping(),
            "failed capture may only be cleaned up, never run"
        );
        assert!(owner.ensure_fresh().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut recovered = open(dir.path());
        assert!(recovered.identity().is_none());
        assert!(recovered.cleanup_pending());
        assert!(recovered
            .stop_owned(
                "boot-one",
                |_| panic!("restart has no captured proof"),
                |_| panic!("restart cannot delete")
            )
            .is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut foreign = identity.clone();
        foreign.index += 1;
        assert!(owner
            .stop_owned(
                "boot-one",
                |_| Ok(Some(foreign.clone())),
                |_| panic!("foreign replacement")
            )
            .is_err());
        assert!(owner
            .stop_owned(
                "boot-one",
                |_| Ok(live.borrow().clone()),
                |saved| {
                    assert_eq!(saved, &identity);
                    *live.borrow_mut() = None;
                    Ok(())
                }
            )
            .is_err());
        assert!(live.borrow().is_none());
        assert_eq!(owner.identity(), Some(&identity));
        assert!(owner.cleanup_pending());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open(dir.path()).identity().is_none());
        owner
            .stop_owned("boot-one", |_| Ok(None), |_| panic!("already gone"))
            .unwrap();
        assert!(!open(dir.path()).cleanup_pending());
    }
}
