use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

const BOOT: &str = "11111111-1111-4111-8111-111111111111";
const JOURNAL: &str = "ordinary-routing/ordinary-routes.json";

fn destination_arg(args: &[String]) -> IpNet {
    match args[3].as_str() {
        "-host" => IpNet::from(args[4].parse::<IpAddr>().unwrap()),
        "-net" => args[4].parse().unwrap(),
        "-dst" => {
            assert_eq!(args[5], "-netmask");
            let mask: std::net::Ipv4Addr = args[6].parse().unwrap();
            IpNet::new(
                args[4].parse().unwrap(),
                u32::from(mask).leading_ones() as u8,
            )
            .unwrap()
        }
        other => panic!("unexpected destination selector: {other}"),
    }
}

#[derive(Default)]
struct Kernel {
    // Native netstat rows, not NetworkValue objects: production parsing and
    // command construction remain under test.
    rows: BTreeMap<String, String>,
    mutations: Vec<Vec<String>>,
    netstat_reads: Vec<String>,
    fail_add: Option<String>,
    lost_add_ack: Option<String>,
    no_op_add: Option<String>,
    fail_delete: bool,
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
            k.netstat_reads.push(args[2].clone());
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
        assert!(matches!(args[3].as_str(), "-host" | "-net" | "-dst"));
        // Every native mutation must already be recoverable on disk.
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&k.journal).expect("write ahead journal"))
                .unwrap();
        let state = &saved["state"]["network"];
        let destination = destination_arg(args);
        assert!(
            state["route_intents"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|intent| {
                    let side = if args[1] == "add" { "after" } else { "before" };
                    intent[side]["destination"] == destination.to_string()
                }),
            "mutation without durable ownership intent: {args:?}"
        );
        k.mutations.push(args.to_vec());
        let name = if args[3] == "-host" {
            destination.addr().to_string()
        } else {
            destination.to_string()
        };
        let destination = &name;
        if args[1] == "delete" {
            if k.fail_delete {
                return Err(io::Error::other("delete EIO"));
            }
            k.rows.remove(destination);
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
        assert_eq!(args[args.len() - 2], "-interface");
        let row = format!("{destination} link#10 USc {}", args.last().unwrap());
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
fn split(
    excluded_networks: &[&str],
    exclude_local_networks: bool,
) -> nelomai_client_tunnel::Ipv4RoutePlan {
    nelomai_client_tunnel::Ipv4RoutePlan {
        policy_hash: None,
        excluded_networks: excluded_networks
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
        exclude_local_networks,
    }
}
fn install(owner: &mut OrdinaryRoutes<Commands>) -> io::Result<()> {
    owner.install("utun10", &allowed(), &endpoints(), &split(&[], false))
}

fn close_owned_link(commands: &Commands) {
    commands
        .0
        .borrow_mut()
        .rows
        .retain(|_, route| route.split_whitespace().nth(3) != Some("utun10"));
}

#[test]
fn routes_only_forwards_batch_and_rejects_dns_before_any_native_read() {
    let commands = Commands(Rc::new(RefCell::new(Kernel::default())));
    let mut routes = RoutesOnly(MacNetwork {
        commands: commands.clone(),
    });
    let keys = ["0.0.0.0/1", "128.0.0.0/2", "::/1"]
        .map(|cidr| ResourceKey::Route(cidr.parse().unwrap(), RouteScope::Global));
    assert_eq!(routes.read_many(&keys).unwrap(), vec![None; 3]);
    assert_eq!(commands.0.borrow().netstat_reads, ["inet", "inet6"]);
    assert!(routes
        .read_many(&[keys[0].clone(), ResourceKey::Dns("Wi-Fi".into())])
        .is_err());
    assert_eq!(commands.0.borrow().netstat_reads.len(), 2);
}

#[test]
fn installs_only_tunnel_routes_and_leaves_existing_uplink_unchanged() {
    let (_dir, commands, mut owner) = setup();
    commands.0.borrow_mut().rows.insert(
        "203.0.113.1".into(),
        "203.0.113.1 192.168.1.2 UGHS en0".into(),
    );
    install(&mut owner).unwrap();
    assert!(owner.has_resources());
    let k = commands.0.borrow();
    for destination in ["64.0.0.0/2", "128.0.0.0/2", "4000::/2", "8000::/1"] {
        assert!(k.rows.contains_key(destination), "{destination}");
    }
    assert!(!k.rows.contains_key("198.51.100.1"));
    drop(k);
    close_owned_link(&commands);
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
    close_owned_link(&commands);
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
fn rejects_foreign_allowed_route_before_any_mutation() {
    let row = "10.99/16 link#20 USc utun20";
    let (_dir, commands, mut owner) = setup();
    commands
        .0
        .borrow_mut()
        .rows
        .insert("10.99/16".into(), row.into());
    assert!(install(&mut owner).is_err(), "{row}");
    assert!(commands.0.borrow().mutations.is_empty());
    assert_eq!(commands.0.borrow().rows.len(), 1);
}

#[test]
fn failed_activation_retires_partial_routes_with_the_link_and_allows_retry() {
    for fault in 0..3 {
        let (_dir, commands, mut owner) = setup();
        {
            let mut k = commands.0.borrow_mut();
            match fault {
                0 => k.fail_add = Some("128.0.0.0/2".into()),
                1 => k.no_op_add = Some("128.0.0.0/2".into()),
                _ => k.lost_add_ack = Some("128.0.0.0/2".into()),
            }
        }
        assert!(install(&mut owner).is_err());
        assert!(commands
            .0
            .borrow()
            .mutations
            .iter()
            .all(|args| args[1] == "add"));
        assert!(owner.has_resources());
        close_owned_link(&commands);
        owner.cleanup().unwrap();
        assert!(commands.0.borrow().rows.is_empty());
        assert!(!owner.has_resources());
        {
            let mut k = commands.0.borrow_mut();
            k.fail_add = None;
            k.no_op_add = None;
            k.lost_add_ack = None;
        }
        install(&mut owner).unwrap();
        assert_eq!(commands.0.borrow().rows.len(), 191);
    }
}

#[test]
fn failed_rollback_survives_restart_and_requires_cleanup_before_retry() {
    let (dir, commands, mut owner) = setup();
    {
        let mut k = commands.0.borrow_mut();
        k.fail_add = Some("128.0.0.0/2".into());
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
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    // The unacknowledged deletions confer no authority after restart.
    commands.0.borrow_mut().rows.clear();
    recovered.cleanup().unwrap();
    assert!(commands.0.borrow().rows.is_empty());
    install(&mut recovered).unwrap();
}

#[test]
fn stop_observes_routes_until_the_owned_link_closes() {
    let (dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    let mutations = commands.0.borrow().mutations.len();
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert_eq!(commands.0.borrow().mutations.len(), mutations);
    assert!(owner.has_resources());
    drop(owner);
    let mut recovered = OrdinaryRoutes::open(
        dir.path(),
        BOOT,
        unsafe { libc::geteuid() },
        commands.clone(),
    )
    .unwrap();
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert!(!commands.0.borrow().rows.is_empty());
    assert!(!commands.0.borrow().rows.contains_key("198.51.100.1"));
    close_owned_link(&commands);
    recovered.cleanup().unwrap();
    assert!(!recovered.has_resources());
}

#[test]
fn foreign_endpoint_appearing_while_connected_survives_stop() {
    let (_dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    let row = "198.51.100.1 192.168.1.2 UGHS en0";
    commands
        .0
        .borrow_mut()
        .rows
        .insert("198.51.100.1".into(), row.into());
    close_owned_link(&commands);
    owner.cleanup().unwrap();
    assert_eq!(commands.0.borrow().rows.values().collect::<Vec<_>>(), [row]);
}

#[test]
fn previous_boot_never_deletes_reused_native_routes() {
    let (dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    assert_eq!(commands.0.borrow().rows.len(), 191);
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
    assert_eq!(commands.0.borrow().rows.len(), 191);
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
    assert_eq!(
        recovered.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert!(commands.0.borrow().rows.contains_key("8000::/1"));
    assert!(commands
        .0
        .borrow()
        .mutations
        .iter()
        .all(|args| args[1] == "add"));
    commands.0.borrow_mut().rows.clear();
    recovered.cleanup().unwrap();
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
            &split(&[], false),
        )
        .unwrap();
    let k = commands.0.borrow();
    assert!(k
        .mutations
        .iter()
        .all(|a| a.ends_with(&["-interface".into(), "utun10".into()])));
    assert!(!k.rows.contains_key("2001:db8::1"));
    assert_eq!(k.rows.len(), 252);
    drop(k);
    close_owned_link(&commands);
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

#[test]
fn every_ordinary_mutation_targets_only_the_vpn_interface() {
    let (_dir, commands, mut owner) = setup();
    install(&mut owner).unwrap();
    let mutations = commands.0.borrow().mutations.clone();
    assert!(mutations
        .iter()
        .all(|args| args.ends_with(&["-interface".into(), "utun10".into()])));
    for args in &mutations {
        let network = destination_arg(args);
        assert!(!network.network().is_unspecified());
        assert!(!network.contains(&endpoints()[0]));
    }
    close_owned_link(&commands);
    owner.cleanup().unwrap();
}

/// The disposable VM harness holds the utun fd. Killing its service process
/// leaves the journal behind; closing the fd removes only that tunnel's rows.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the disposable macOS VM and its independently owned test utun"]
fn native_ordinary_route_lifecycle() {
    use crate::member_network::macos::NativeMacCommands;
    use std::process::Command;
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let vm_model = Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.model"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&vm_model.stdout).contains("VirtualMac"));
    let root = std::path::PathBuf::from(std::env::var_os("NELOMAI_ROUTE_QA_ROOT").unwrap());
    let boot = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.bootsessionuuid"])
        .output()
        .unwrap();
    let mut owner = OrdinaryRoutes::open(
        &root,
        std::str::from_utf8(&boot.stdout).unwrap().trim(),
        0,
        NativeMacCommands,
    )
    .unwrap();
    let stage = std::env::var("NELOMAI_ROUTE_QA_STAGE").unwrap();
    if stage == "recover" {
        assert!(owner.has_resources());
        owner.cleanup().unwrap();
        assert!(!owner.has_resources());
        return;
    }
    assert!(matches!(stage.as_str(), "apply-stop" | "crash"));
    let interface = std::env::var("OWNED_TEST_UTUN").unwrap();
    let mut native = NativeMacCommands;
    let physical = |native: &mut NativeMacCommands, ip: &str| {
        physical_endpoint(native, ip.parse().unwrap()).unwrap()
    };
    let peer = "1.1.1.1";
    let excluded = "198.19.237.21";
    let sample = "198.19.237.22";
    let before = physical(&mut native, excluded);
    let peer_before = physical(&mut native, peer);
    let full = std::env::var_os("NELOMAI_ROUTE_QA_FULL").is_some();
    let networks = if full {
        vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]
    } else {
        vec!["198.19.237.0/24".parse().unwrap()]
    };
    owner
        .install(
            &interface,
            &networks,
            &[peer.parse().unwrap()],
            &split(&["198.19.237.21/32"], false),
        )
        .unwrap();
    assert_eq!(before, physical(&mut native, excluded));
    assert_eq!(peer_before, physical(&mut native, peer));
    let out = native
        .run(
            "/sbin/route",
            &["-n".into(), "get".into(), "-inet".into(), sample.into()],
        )
        .unwrap();
    assert!(out.lines().any(|line| line
        .trim()
        .split_once(':')
        .is_some_and(|(k, v)| k == "interface" && v.trim() == interface)));
    if full {
        let url = std::env::var("NELOMAI_ROUTE_QA_PANEL_URL").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let history = rt
            .block_on(async {
                nelomai_client_api::ClientApi::new(&url)
                    .unwrap()
                    .release_history(nelomai_contracts::Platform::Macos)
                    .await
            })
            .unwrap();
        assert_eq!(history.platform, nelomai_contracts::Platform::Macos);
    }
    if stage == "crash" {
        std::process::exit(79);
    }
    // The harness still holds the link FD in this process. The production
    // cleanup must leave these rows intact until that FD closes.
    assert_eq!(
        owner.cleanup().unwrap_err().to_string(),
        "network_route_ownership_unconfirmed"
    );
    assert!(owner.has_resources());
}
