use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const JOURNAL: &str = "ordinary-routing/ordinary-routes.json";

#[derive(Default)]
struct Kernel {
    // Native netstat rows, not NetworkValue objects: production parsing and
    // command construction remain under test.
    rows: BTreeMap<String, String>,
    mutations: Vec<Vec<String>>,
    fail_add: Option<String>,
    lost_add_ack: Option<String>,
    no_op_add: Option<String>,
    fail_delete: bool,
    no_op_delete: bool,
    lookup: Option<String>,
    forbid_native: bool,
    fail_commit_after: Option<String>,
    journal: std::path::PathBuf,
}
#[derive(Clone)]
struct Commands(Rc<RefCell<Kernel>>);
impl MacNetworkCommands for Commands {
    fn run(&mut self, program: &str, args: &[String]) -> io::Result<String> {
        let mut k = self.0.borrow_mut();
        assert!(
            !k.forbid_native,
            "unexpected native command during boot retirement"
        );
        if program == "/usr/sbin/netstat" {
            assert_eq!(&args[..2], ["-rn", "-f"]);
            let v6 = args[2] == "inet6";
            return Ok(format!(
                "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n{}",
                k.rows
                    .values()
                    .filter(|r| r.split_whitespace().next().unwrap().contains(':') == v6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
        assert_eq!(
            program, "/sbin/route",
            "ordinary routing must never touch DNS"
        );
        assert_eq!(args[0], "-n");
        if args[1] == "get" {
            assert_eq!(args.len(), 4);
            return Ok(k.lookup.clone().unwrap_or_else(|| format!(
                "   route to: {}\ndestination: default\n       mask: default\n    gateway: {}\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire\n 0 0 0 0 0 0 1500 0\n",
                args[3], if args[2] == "-inet6" { "fe80::1%en0" } else { "192.168.1.1" })));
        }
        assert!(matches!(args[1].as_str(), "add" | "delete"));
        assert!(matches!(args[3].as_str(), "-host" | "-net"));
        // Every native mutation must already be recoverable on disk.
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&k.journal).expect("write ahead journal"))
                .unwrap();
        let state = &saved["state"]["network"];
        let destination: IpNet = if args[3] == "-host" {
            IpNet::from(args[4].parse::<IpAddr>().unwrap())
        } else {
            args[4].parse().unwrap()
        };
        assert!(
            state["owned"]
                .as_array()
                .into_iter()
                .flatten()
                .chain(state["pending"]["target"].as_array().into_iter().flatten())
                .any(|entry| entry["current"]["Route"]["destination"] == destination.to_string()),
            "mutation without durable ownership intent: {args:?}"
        );
        k.mutations.push(args.to_vec());
        let destination = &args[4];
        if args[1] == "delete" {
            if k.fail_delete {
                return Err(io::Error::other("delete EIO"));
            }
            if !k.no_op_delete {
                k.rows.remove(destination);
            }
            return Ok(String::new());
        }
        if k.fail_add.as_ref() == Some(destination) {
            return Err(io::Error::other("add EIO"));
        }
        if k.no_op_add.as_ref() == Some(destination) {
            return Ok(String::new());
        }
        if k.rows.contains_key(destination) {
            return Err(io::Error::other("File exists"));
        }
        let row = if args[5] == "-interface" {
            assert_eq!(args.len(), 7);
            format!("{destination} link#10 USc {}", args[6])
        } else {
            assert_eq!(args.len(), 6);
            format!("{destination} {} UGHS en0", args[5])
        };
        k.rows.insert(destination.clone(), row);
        if k.fail_commit_after.as_ref() == Some(destination) {
            std::fs::set_permissions(&k.journal, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        if k.lost_add_ack.as_ref() == Some(destination) {
            return Err(io::Error::other("lost add ack"));
        }
        Ok(String::new())
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
        match index {
            5 => Ok("en0".into()),
            10 => Ok("utun10".into()),
            20 => Ok("utun20".into()),
            _ => Err(io::Error::other("unknown index")),
        }
    }
    fn interface_index(&self, name: &str) -> io::Result<u32> {
        match name {
            "en0" => Ok(5),
            "utun10" => Ok(10),
            "utun20" => Ok(20),
            _ => Err(io::Error::other("unknown interface")),
        }
    }
}
fn setup() -> (tempfile::TempDir, Commands, OrdinaryRoutes<Commands>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let commands = Commands(Rc::new(RefCell::new(Kernel {
        journal: dir.path().join(JOURNAL),
        ..Default::default()
    })));
    let owner = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    (dir, commands, owner)
}
fn allowed() -> Vec<IpNet> {
    ["0.0.0.0/0", "::/0", "10.99.0.0/16"]
        .map(|s| s.parse().unwrap())
        .to_vec()
}
fn endpoints() -> Vec<IpAddr> {
    vec!["198.51.100.1".parse().unwrap()]
}
fn install(owner: &mut OrdinaryRoutes<Commands>) -> io::Result<()> {
    owner.install("utun10", &allowed(), &endpoints())
}

#[test]
fn installs_all_allowed_routes_and_endpoint_before_data_then_cleans_owned_only() {
    let (_dir, commands, mut owner) = setup();
    commands.0.borrow_mut().rows.insert(
        "203.0.113.1".into(),
        "203.0.113.1 192.168.1.2 UGHS en0".into(),
    );
    install(&mut owner).unwrap();
    assert!(owner.has_resources());
    let k = commands.0.borrow();
    assert_eq!(k.mutations[0][4], "198.51.100.1");
    for destination in [
        "0.0.0.0/1",
        "128.0.0.0/1",
        "::/1",
        "8000::/1",
        "10.99.0.0/16",
    ] {
        assert!(k.rows.contains_key(destination), "{destination}");
    }
    drop(k);
    owner.cleanup().unwrap();
    assert!(!owner.has_resources());
    assert_eq!(commands.0.borrow().rows.len(), 1);
}

#[test]
fn retains_identical_physical_endpoint_without_acquiring_cleanup_authority() {
    let (_dir, commands, mut owner) = setup();
    let row = "198.51.100.1 192.168.1.1 UGHS en0";
    commands
        .0
        .borrow_mut()
        .rows
        .insert("198.51.100.1".into(), row.into());
    install(&mut owner).unwrap();
    assert!(owner.has_resources());
    owner.cleanup().unwrap();
    assert_eq!(commands.0.borrow().rows.get("198.51.100.1").unwrap(), row);
    assert!(commands
        .0
        .borrow()
        .mutations
        .iter()
        .all(|a| a[4] != "198.51.100.1"));
}

#[test]
fn rejects_foreign_endpoint_or_allowed_route_before_any_mutation() {
    for row in [
        "198.51.100.1 192.168.1.2 UGHS en0",
        "0/1 link#20 USc utun20",
        "10.99/16 link#10 USc utun10",
    ] {
        let (_dir, commands, mut owner) = setup();
        commands
            .0
            .borrow_mut()
            .rows
            .insert(row.split_whitespace().next().unwrap().into(), row.into());
        assert!(install(&mut owner).is_err(), "{row}");
        assert!(commands.0.borrow().mutations.is_empty());
        assert_eq!(commands.0.borrow().rows.len(), 1);
    }
}

#[test]
fn add_errors_and_false_success_roll_back_partial_routes_and_allow_retry() {
    for fault in 0..3 {
        let (_dir, commands, mut owner) = setup();
        {
            let mut k = commands.0.borrow_mut();
            match fault {
                0 => k.fail_add = Some("128.0.0.0/1".into()),
                1 => k.no_op_add = Some("128.0.0.0/1".into()),
                _ => k.lost_add_ack = Some("128.0.0.0/1".into()),
            }
        }
        assert!(install(&mut owner).is_err());
        assert!(commands.0.borrow().rows.is_empty());
        assert!(!owner.has_resources());
        {
            let mut k = commands.0.borrow_mut();
            k.fail_add = None;
            k.no_op_add = None;
            k.lost_add_ack = None;
        }
        install(&mut owner).unwrap();
        assert_eq!(commands.0.borrow().rows.len(), 6);
    }
}

#[test]
fn failed_rollback_survives_restart_and_requires_cleanup_before_retry() {
    let (dir, commands, mut owner) = setup();
    {
        let mut k = commands.0.borrow_mut();
        k.fail_add = Some("128.0.0.0/1".into());
        k.fail_delete = true;
    }
    assert!(install(&mut owner).is_err());
    assert!(owner.has_resources());
    drop(owner);
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    assert!(recovered.has_resources());
    assert!(install(&mut recovered).is_err());
    assert!(recovered.cleanup().is_err());
    {
        let mut k = commands.0.borrow_mut();
        k.fail_add = None;
        k.fail_delete = false;
    }
    recovered.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
    install(&mut recovered).unwrap();
}

#[test]
fn stop_checks_deletion_readback_and_keeps_journal_for_retry() {
    let (dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    commands.0.borrow_mut().no_op_delete = true;
    assert!(owner.cleanup().is_err());
    assert!(owner.has_resources());
    drop(owner);
    commands.0.borrow_mut().no_op_delete = false;
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    recovered.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
}

#[test]
fn foreign_replacement_blocks_cleanup_and_is_never_deleted() {
    let (_dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    let row = "198.51.100.1 192.168.1.2 UGHS en0";
    commands
        .0
        .borrow_mut()
        .rows
        .insert("198.51.100.1".into(), row.into());
    assert!(owner.cleanup().is_err());
    assert!(owner.has_resources());
    assert_eq!(commands.0.borrow().rows.get("198.51.100.1").unwrap(), row);
}

#[test]
fn previous_boot_never_deletes_reused_native_routes() {
    let (dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    assert_eq!(commands.0.borrow().rows.len(), 6);
    drop(owner);
    commands.0.borrow_mut().forbid_native = true;
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        "22222222-2222-4222-8222-222222222222",
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    recovered.cleanup().unwrap();
    assert_eq!(commands.0.borrow().rows.len(), 6);
    assert!(!recovered.has_resources());
}

#[test]
fn journal_write_failure_prevents_any_native_effect() {
    let (dir, commands, mut owner) = setup();
    symlink(dir.path().join("missing"), dir.path().join(JOURNAL)).unwrap();
    assert!(install(&mut owner).is_err());
    assert!(commands.0.borrow().mutations.is_empty());
}

#[test]
fn unsafe_effective_endpoint_route_is_rejected() {
    for output in [
        "gateway: 10.0.0.1\ninterface: utun20\nflags: <UP,GATEWAY,DONE>\n",
        "gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,REJECT>\n",
        "gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,BLACKHOLE>\n",
    ] {
        let (_dir, commands, mut owner) = setup();
        commands.0.borrow_mut().lookup = Some(output.into());
        assert!(install(&mut owner).is_err());
        assert!(commands.0.borrow().mutations.is_empty());
    }
}

#[test]
fn ordinary_runtime_can_be_searchable_but_journal_directory_must_be_private() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let commands = Commands(Rc::new(RefCell::new(Kernel::default())));
    OrdinaryRoutes::open(dir.path(), BOOT, unsafe { libc::geteuid() }, commands).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(dir.path().join("ordinary-routing"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn commit_failure_keeps_pending_intent_and_restart_can_finish_cleanup() {
    let (dir, commands, mut owner) = setup();
    commands.0.borrow_mut().fail_commit_after = Some("8000::/1".into());
    assert!(install(&mut owner).is_err());
    assert!(owner.has_resources());
    assert!(install(&mut owner).is_err());
    drop(owner);
    std::fs::set_permissions(
        dir.path().join(JOURNAL),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    recovered.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
    assert!(!recovered.has_resources());
}

#[test]
fn ipv6_endpoint_preserves_gateway_zone_and_duplicate_allowed_ips_are_installed_once() {
    let (_dir, commands, mut owner) = setup();
    owner
        .install(
            "utun10",
            &[
                "::/0".parse().unwrap(),
                "::/1".parse().unwrap(),
                "8000::/1".parse().unwrap(),
            ],
            &[
                "2001:db8::1".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        )
        .unwrap();
    let k = commands.0.borrow();
    assert_eq!(
        k.mutations[0],
        ["-n", "add", "-inet6", "-host", "2001:db8::1", "fe80::1%en0"]
    );
    assert_eq!(k.rows.len(), 3);
    drop(k);
    owner.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
}

#[test]
fn legacy_endpoints_file_confers_no_deletion_authority() {
    let (dir, commands, mut owner) = setup();
    std::fs::write(
        dir.path().join("endpoints-state.json"),
        b"[\"198.51.100.1:51820\"]",
    )
    .unwrap();
    commands.0.borrow_mut().rows.insert(
        "198.51.100.1".into(),
        "198.51.100.1 192.168.1.2 UGHS en0".into(),
    );
    commands.0.borrow_mut().forbid_native = true;
    owner.cleanup().unwrap();
    drop(owner);
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    recovered.cleanup().unwrap();
    assert_eq!(commands.0.borrow().rows.len(), 1);
    assert!(commands.0.borrow().mutations.is_empty());
}

#[test]
fn successful_install_is_cleanup_only_after_restart_and_handles_kernel_removed_routes() {
    let (dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    drop(owner);
    commands
        .0
        .borrow_mut()
        .rows
        .retain(|destination, _| destination == "198.51.100.1");
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    assert!(install(&mut recovered).is_err());
    recovered.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
    install(&mut recovered).unwrap();
}

#[test]
fn private_directory_symlink_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), dir.path().join("ordinary-routing")).unwrap();
    let commands = Commands(Rc::new(RefCell::new(Kernel::default())));
    assert!(OrdinaryRoutes::open(dir.path(), BOOT, unsafe { libc::geteuid() }, commands).is_err());
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
}
