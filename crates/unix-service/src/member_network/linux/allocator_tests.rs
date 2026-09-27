use super::*;
use bindings::BindingAllocator;
use nelomai_client_tunnel::redundancy::{SessionScope, Slot};
use nelomai_contracts::RuntimeSlot;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn scope() -> SessionScope {
    SessionScope {
        runtime: RuntimeSlot::Latest,
        runtime_generation: 7,
        session_id: "72cc17e2-0000-4000-8000-000000000001".into(),
        connection_generation: 2,
    }
}
fn directory() -> tempfile::TempDir {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.tmp");
    fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("linux-network-bindings-")
        .tempdir_in(base)
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn allocator(root: &Path, fresh: bool) -> BindingAllocator {
    BindingAllocator::open_for_owner(root, scope(), "boot-one", unsafe { libc::geteuid() }, fresh)
        .unwrap()
}

struct Commands {
    dumps: [String; 4],
    calls: Vec<Vec<String>>,
    fail: bool,
    replace_after_dump: bool,
    a_index: u32,
}
impl Default for Commands {
    fn default() -> Self {
        Self {
            dumps: std::array::from_fn(|_| "[]".into()),
            calls: vec![],
            fail: false,
            replace_after_dump: false,
            a_index: 10,
        }
    }
}
impl LinuxNetworkCommands for Commands {
    fn ip(&mut self, args: &[String]) -> io::Result<String> {
        let args_str: Vec<_> = args.iter().map(String::as_str).collect();
        let dump = match args_str.as_slice() {
            ["-j", "-N", "-4", "route", "show", "table", "all"] => 0,
            ["-j", "-N", "-6", "route", "show", "table", "all"] => 1,
            ["-j", "-N", "-4", "rule", "show"] => 2,
            ["-j", "-N", "-6", "rule", "show"] => 3,
            _ => panic!("unexpected native operation: {args:?}"),
        };
        self.calls.push(args.to_vec());
        if self.fail {
            return Err(io::Error::other("fake read failure"));
        }
        if dump == 3 && self.replace_after_dump {
            self.a_index = 99;
        }
        Ok(self.dumps[dump].clone())
    }
    fn busctl(&mut self, args: &[String]) -> io::Result<String> {
        panic!("unexpected busctl: {args:?}")
    }
    fn interface_name(&self, index: u32) -> io::Result<String> {
        match index {
            i if i == self.a_index => Ok("nlm-wga".into()),
            20 => Ok("nlm-awgb".into()),
            _ => Err(io::ErrorKind::NotFound.into()),
        }
    }
    fn interface_index(&self, name: &str) -> io::Result<u32> {
        match name {
            "nlm-wga" => Ok(self.a_index),
            "nlm-awgb" => Ok(20),
            _ => Err(io::ErrorKind::NotFound.into()),
        }
    }
}
fn adapter(root: &Path, fresh: bool) -> LinuxNetwork<Commands> {
    LinuxNetwork::with_allocator(Commands::default(), allocator(root, fresh)).unwrap()
}
fn rule(interface: u32, table: u32, priority: u32, ipv6: bool) -> NetworkValue {
    NetworkValue::BoundRule(BoundRuleValue {
        interface,
        table,
        priority,
        ipv6,
    })
}

#[test]
fn fresh_primary_then_late_standby_publish_distinct_durable_rules() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    assert!(network.member_rule(10, false).is_err());
    network.member_started(Slot::A, 10).unwrap();
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    assert!(network.member_rule(20, false).is_err());
    network.member_started(Slot::B, 20).unwrap();
    assert_eq!(
        network.member_rule(10, true).unwrap(),
        rule(10, 30000, 10000, true)
    );
    assert_eq!(
        network.member_rule(20, false).unwrap(),
        rule(20, 30001, 10001, false)
    );
    assert_eq!(network.commands.calls.len(), 8);
    let saved = allocator(dir.path(), false);
    assert_eq!(
        saved
            .bindings()
            .iter()
            .map(|b| (b.index, b.table, b.priority))
            .collect::<Vec<_>>(),
        [(10, 30000, 10000), (20, 30001, 10001)]
    );
}

#[test]
fn both_family_route_and_rule_collisions_are_excluded_before_publish() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.commands.dumps = [
        r#"[{"table":30000}]"#.into(),
        r#"[{"table":30001}]"#.into(),
        r#"[{"priority":10000,"table":30002}]"#.into(),
        r#"[{"priority":10001,"action":"blackhole"}]"#.into(),
    ];
    network.member_started(Slot::A, 10).unwrap();
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30003, 10002, false)
    );
    network.member_started(Slot::B, 20).unwrap();
    assert_eq!(
        network.member_rule(20, true).unwrap(),
        rule(20, 30004, 10003, true)
    );
}

#[test]
fn exact_duplicate_is_stable_without_new_occupancy_reads() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    network.commands.fail = true;
    network.member_started(Slot::A, 10).unwrap();
    assert_eq!(network.commands.calls.len(), 4);
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    assert!(network.member_started(Slot::B, 10).is_err());
    network.commands.a_index = 99;
    assert!(network.member_started(Slot::A, 99).is_err());
    assert_eq!(allocator(dir.path(), false).bindings()[0].index, 10);
}

#[test]
fn write_failure_never_publishes_standby_or_changes_primary() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = network.member_started(Slot::B, 20);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert!(network.member_rule(20, false).is_err());
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    assert_eq!(allocator(dir.path(), false).bindings().len(), 1);
    assert!(network.member_started(Slot::B, 20).is_err());
}

#[test]
fn recovery_restores_cleanup_bindings_but_never_adopts_a_live_member() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    drop(network);
    let mut recovered = adapter(dir.path(), false);
    assert_eq!(
        recovered.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    assert!(recovered.member_started(Slot::A, 10).is_err());
    assert!(recovered.member_started(Slot::B, 20).is_err());
    assert!(recovered.commands.calls.is_empty());
    recovered.session_closed().unwrap();
    assert!(recovered.member_rule(10, false).is_err());
    assert!(allocator(dir.path(), false).bindings().is_empty());
}

#[test]
fn close_retries_failed_release_and_fences_future_allocation() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    network.member_started(Slot::B, 20).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let result = network.session_closed();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(allocator(dir.path(), false).bindings().len(), 2);
    assert!(network.member_started(Slot::A, 10).is_err());
    network.session_closed().unwrap();
    network.session_closed().unwrap();
    assert!(allocator(dir.path(), false).bindings().is_empty());
    assert!(network.member_rule(10, false).is_err());
    assert!(network.member_started(Slot::A, 10).is_err());
}

#[test]
fn identity_replaced_during_occupancy_reads_is_not_reserved() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.commands.replace_after_dump = true;
    assert!(network.member_started(Slot::A, 10).is_err());
    assert!(network.member_rule(10, false).is_err());
    assert!(allocator(dir.path(), false).bindings().is_empty());
}

#[test]
fn manual_registration_cannot_bypass_allocator_durability() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    assert!(network
        .register_member(MemberTable {
            interface: 10,
            name: "nlm-wga".into(),
            table: 40000,
            priority: 20000
        })
        .is_err());
    assert!(network.member_rule(10, false).is_err());
}

#[test]
fn malformed_or_failed_dump_keeps_all_bindings_unpublished() {
    for bad in [r#"[{"table":"main"}]"#, "not json"] {
        let dir = directory();
        let mut network = adapter(dir.path(), true);
        network.commands.dumps[1] = bad.into();
        assert!(network.member_started(Slot::A, 10).is_err());
        assert!(network.member_rule(10, false).is_err());
        assert!(allocator(dir.path(), false).bindings().is_empty());
    }
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.commands.fail = true;
    assert!(network.member_started(Slot::A, 10).is_err());
    assert!(allocator(dir.path(), false).bindings().is_empty());
}

#[test]
fn native_binding_release_b_keeps_a_and_allows_standby_reuse() {
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    network.member_started(Slot::B, 20).unwrap();
    assert!(network.member_stopped(Slot::B, 10).is_err());
    assert!(network.member_stopped(Slot::B, 99).is_err());
    // Caller has now confirmed exact B and all its network resources absent.
    network.member_stopped(Slot::B, 20).unwrap();
    network.member_stopped(Slot::B, 20).unwrap();
    assert!(network.member_rule(20, false).is_err());
    assert_eq!(
        network.member_rule(10, true).unwrap(),
        rule(10, 30000, 10000, true)
    );
    let saved = allocator(dir.path(), false);
    assert_eq!(saved.bindings().len(), 1);
    assert_eq!(saved.bindings()[0].index, 10);
    assert_eq!(network.commands.calls.len(), 8);
    network.member_started(Slot::B, 20).unwrap();
    assert_eq!(
        network.member_rule(20, true).unwrap(),
        rule(20, 30001, 10001, true)
    );
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
}

#[test]
fn member_release_write_failure_keeps_exact_b_for_retry_and_reopen() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let dir = directory();
    let mut network = adapter(dir.path(), true);
    network.member_started(Slot::A, 10).unwrap();
    network.member_started(Slot::B, 20).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = network.member_stopped(Slot::B, 20);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
    assert_eq!(
        network.member_rule(20, false).unwrap(),
        rule(20, 30001, 10001, false)
    );
    assert_eq!(allocator(dir.path(), false).bindings().len(), 2);
    network.member_stopped(Slot::B, 20).unwrap();
    assert!(network.member_rule(20, false).is_err());
    assert_eq!(
        network.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    drop(network);
    let mut recovered = adapter(dir.path(), false);
    recovered.member_stopped(Slot::B, 20).unwrap();
    assert_eq!(
        recovered.member_rule(10, false).unwrap(),
        rule(10, 30000, 10000, false)
    );
    assert!(recovered.member_started(Slot::B, 20).is_err());
    assert!(recovered.commands.calls.is_empty());
}
