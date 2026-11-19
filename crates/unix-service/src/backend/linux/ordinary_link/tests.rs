use super::*;
use crate::backend::linux::LinuxBackend;
use crate::{ServiceTunnelBackend, ServiceTunnelState};
use nelomai_contracts::dispatcher::TunnelSlot;
use std::sync::{Mutex, MutexGuard};

#[test]
fn legacy_captured_wireguard_and_awg_journals_remain_readable() {
    for (interface, proof) in [
        ("nlm-wg0", serde_json::json!({"Kernel":{"group":42}})),
        (
            "nlm-awg0",
            serde_json::json!({"Userspace":{"device":7,"inode":9}}),
        ),
    ] {
        let legacy = serde_json::json!({
            "identity":{"boot":"boot-id","interface":interface,"index":3,"proof":proof},
            "ready":true,
            "dns_entry":interface,
        });
        let Phase::Owned(record) = serde_json::from_value::<Phase>(legacy.clone()).unwrap() else {
            panic!("a captured link must reopen as owned");
        };
        assert!(record.ready);
        assert_eq!(record.awg_group, None);
        assert_eq!(serde_json::to_value(Phase::Owned(record)).unwrap(), legacy);
    }
}

fn isolated() -> MutexGuard<'static, ()> {
    static NETWORK: Mutex<()> = Mutex::new(());
    assert_eq!(
        std::env::var("NELOMAI_ALLOW_DISPOSABLE_VM").as_deref(),
        Ok("1")
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    NETWORK.lock().unwrap()
}

fn interrupted(runtime: &Path, transport: MemberTransport, group: u32) -> Intent {
    let boot = boot_identity().unwrap();
    let launch = Intent {
        boot,
        transport,
        group,
    };
    let mut store = OrdinaryLinkStore::open(runtime).unwrap();
    store.phase = Some(Phase::Starting(Starting {
        launch: launch.clone(),
    }));
    store.persist().unwrap();
    launch
}

#[test]
#[ignore = "requires root in a disposable Linux network and mount namespace"]
fn interrupted_wireguard_launch_is_cleanup_only_and_keeps_foreign_links() {
    let _network = isolated();
    let runtime = tempfile::tempdir().unwrap();
    let launch = interrupted(runtime.path(), MemberTransport::WireGuard, 90123);
    let interface = launch.interface(MODE);

    // A crash before NEWLINK would leave exactly this journal and no link.
    let mut service = LinuxBackend::new("/unused/amneziawg-go", runtime.path()).unwrap();
    assert_eq!(service.status().unwrap(), ServiceTunnelState::Stopping);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    drop(service);
    let launch = interrupted(runtime.path(), MemberTransport::WireGuard, 90123);

    LinuxOrdinaryRoutes::create_wireguard_link(interface, 90124).unwrap();
    let foreign_index = kernel_interface_index(interface).unwrap();
    assert!(LinuxBackend::new("/unused/amneziawg-go", runtime.path()).is_err());
    assert_eq!(kernel_interface_index(interface).unwrap(), foreign_index);
    LinuxOrdinaryRoutes::delete_link(foreign_index).unwrap();

    // NEWLINK completed but the launcher died before recording its index.
    LinuxOrdinaryRoutes::create_wireguard_link(interface, launch.group).unwrap();
    let mut service = LinuxBackend::new("/unused/amneziawg-go", runtime.path()).unwrap();
    assert_eq!(service.status().unwrap(), ServiceTunnelState::Stopping);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    assert_eq!(kernel_interface_index(interface).unwrap(), 0);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
}

#[test]
#[ignore = "requires root in a disposable Linux network and mount namespace with private /run"]
fn interrupted_awg_launch_cleans_the_private_socket_after_the_tun_fd_closes() {
    let _network = isolated();
    let runtime = tempfile::tempdir().unwrap();
    let launch = interrupted(runtime.path(), MemberTransport::AmneziaWg3, 90125);
    let interface = launch.interface(MODE);
    let canonical = userspace_socket_path(interface);
    let directory = canonical.parent().unwrap();
    create_directory(directory, 0o755).unwrap();
    create_directory(&staging_directory(directory), 0o700).unwrap();
    let stage = stage_path(interface, launch.group).unwrap();
    {
        let _tun = create_tun(interface).unwrap();
        let _listener = UnixListener::bind(&stage).unwrap();
        assert_ne!(kernel_interface_index(interface).unwrap(), 0);
    }
    assert_eq!(kernel_interface_index(interface).unwrap(), 0);
    assert!(socket_at(&stage).unwrap().is_some());
    let mut service = LinuxBackend::new("/unused/amneziawg-go", runtime.path()).unwrap();
    assert_eq!(service.status().unwrap(), ServiceTunnelState::Stopping);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    assert!(socket_at(&canonical).unwrap().is_none());
    assert!(socket_at(&stage).unwrap().is_none());
}

#[test]
#[ignore = "requires root in a disposable Linux network and mount namespace with private /run"]
fn interrupted_awg_handoff_unlinks_only_the_captured_socket() {
    let _network = isolated();
    let runtime = tempfile::tempdir().unwrap();
    let launch = interrupted(runtime.path(), MemberTransport::AmneziaWg3, 90126);
    let mut store = OrdinaryLinkStore::open(runtime.path()).unwrap();
    let interface = launch.interface(MODE);
    let canonical = userspace_socket_path(interface);
    let directory = canonical.parent().unwrap();
    create_directory(directory, 0o755).unwrap();
    create_directory(&staging_directory(directory), 0o700).unwrap();
    let stage = stage_path(interface, launch.group).unwrap();
    {
        let _tun = create_tun(interface).unwrap();
        let index = kernel_interface_index(interface).unwrap();
        LinuxOrdinaryRoutes::set_link_group(index, launch.group).unwrap();
        let _listener = UnixListener::bind(&stage).unwrap();
        let socket = socket_at(&stage).unwrap().unwrap();
        let identity = LinuxIdentity {
            boot: launch.boot,
            interface: interface.into(),
            index,
            proof: NativeProof::Userspace(socket),
        };
        store.capture(identity, Some(launch.group)).unwrap();
        publish_socket(&stage, &canonical).unwrap();
    }
    let other = directory.join("foreign-awg.sock");
    fs::rename(&canonical, &other).unwrap();
    let _foreign = UnixListener::bind(&canonical).unwrap();
    assert!(LinuxBackend::new("/unused/amneziawg-go", runtime.path()).is_err());
    assert!(socket_at(&canonical).unwrap().is_some());
    fs::remove_file(&canonical).unwrap();
    fs::rename(other, &canonical).unwrap();
    let mut service = LinuxBackend::new("/unused/amneziawg-go", runtime.path()).unwrap();
    assert_eq!(service.status().unwrap(), ServiceTunnelState::Stopping);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    assert!(socket_at(&canonical).unwrap().is_none());
}

#[test]
#[ignore = "requires root in a disposable Linux network and mount namespace with private /run"]
fn crashed_awg_member_retires_only_its_own_socket() {
    let _network = isolated();
    let runtime = tempfile::tempdir().unwrap();
    let interface = "nlm-awga";
    let socket_path = userspace_socket_path(interface);
    create_directory(socket_path.parent().unwrap(), 0o755).unwrap();
    create_directory(&runtime.path().join("slot-a"), 0o700).unwrap();
    let scope = nelomai_client_tunnel::redundancy::SessionScope {
        runtime: nelomai_contracts::RuntimeSlot::Latest,
        runtime_generation: 1,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 1,
    };
    let mut service =
        LinuxBackend::new_member("/unused/amneziawg-go", runtime.path(), TunnelSlot::A, scope)
            .unwrap();
    let boot = boot_identity().unwrap();
    {
        let _tun = create_tun(interface).unwrap();
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let identity = capture_member(interface, MemberTransport::AmneziaWg3, &boot).unwrap();
        let owner = service.member_owner.as_mut().unwrap();
        owner.begin(MemberTransport::AmneziaWg3, &boot).unwrap();
        owner.capture(identity).unwrap();
    }
    assert_eq!(kernel_interface_index(interface).unwrap(), 0);
    let saved_path = socket_path.with_extension("saved");
    fs::rename(&socket_path, &saved_path).unwrap();
    let _foreign = UnixListener::bind(&socket_path).unwrap();
    let foreign = socket_at(&socket_path).unwrap().unwrap();
    assert!(service.stop().is_err());
    assert_eq!(socket_at(&socket_path).unwrap(), Some(foreign));
    fs::rename(saved_path, &socket_path).unwrap();

    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    assert!(socket_at(&socket_path).unwrap().is_none());
}

#[test]
#[ignore = "requires root in a disposable Linux network and mount namespace with private /run"]
fn stopping_awg_member_waits_for_its_tun_after_uapi_closes() {
    let _network = isolated();
    let runtime = tempfile::tempdir().unwrap();
    let interface = "nlm-awga";
    let socket_path = userspace_socket_path(interface);
    create_directory(socket_path.parent().unwrap(), 0o755).unwrap();
    create_directory(&runtime.path().join("slot-a"), 0o700).unwrap();
    let scope = SessionScope {
        runtime: nelomai_contracts::RuntimeSlot::Latest,
        runtime_generation: 1,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 1,
    };
    let mut service =
        LinuxBackend::new_member("/unused/amneziawg-go", runtime.path(), TunnelSlot::A, scope)
            .unwrap();
    let boot = boot_identity().unwrap();
    let tun = create_tun(interface).unwrap();
    let listener = UnixListener::bind(&socket_path).unwrap();
    let identity = capture_member(interface, MemberTransport::AmneziaWg3, &boot).unwrap();
    let owner = service.member_owner.as_mut().unwrap();
    owner.begin(MemberTransport::AmneziaWg3, &boot).unwrap();
    owner.capture(identity.clone()).unwrap();

    // AWG closes and unlinks its UAPI listener before releasing the TUN.
    drop(listener);
    fs::remove_file(&socket_path).unwrap();
    let foreign = create_tun("p2-foreign").unwrap();
    let foreign_index = kernel_interface_index("p2-foreign").unwrap();
    assert_eq!(kernel_interface_index(interface).unwrap(), identity.index);
    assert!(socket_at(&socket_path).unwrap().is_none());
    let close_tun = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(250));
        drop(tun);
    });
    let stopped = service.stop();
    close_tun.join().unwrap();

    assert_eq!(stopped.unwrap(), ServiceTunnelState::Stopped);
    assert_eq!(kernel_interface_index(interface).unwrap(), 0);
    assert_eq!(kernel_interface_index("p2-foreign").unwrap(), foreign_index);
    assert_eq!(service.stop().unwrap(), ServiceTunnelState::Stopped);
    drop(foreign);
}
