use super::*;
use crate::member_network::linux::{
    bindings::{BindingAllocator, Occupancy},
    LinuxNetworkCommands,
};
use crate::{ParsedConfiguration, ServiceError, ServiceTunnelBackend, ServiceTunnelState};
use nelomai_client_tunnel::{redundancy::Slot, DesktopTunnelOptions};
use nelomai_contracts::{
    dispatcher::TunnelSlot, HealthProbeKind, RedundantHealthProbe, RuntimeSlot,
};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
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
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.tmp");
    fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("linux-pair-factory-")
        .tempdir_in(base)
        .unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn boot_only(root: &Path) {
    ScopedJournal::<Boot>::open_named(root, scope(), uid(), "redundant-session.json")
        .unwrap()
        .save_state(&Boot {
            identity: "boot-one".into(),
        })
        .unwrap();
}

#[derive(Default)]
struct Events {
    calls: Vec<String>,
    fail_b_constructor: bool,
    fail_commands_constructor: bool,
    pending_a: bool,
    fail_a_stop: bool,
}
struct Backend {
    slot: TunnelSlot,
    events: Arc<Mutex<Events>>,
}
impl ServiceTunnelBackend for Backend {
    fn member_slot(&self) -> Option<TunnelSlot> {
        Some(self.slot)
    }
    fn member_recovery_scope(&self) -> Option<SessionScope> {
        Some(scope())
    }
    fn member_cleanup_pending(&self) -> bool {
        self.slot == TunnelSlot::A && self.events.lock().unwrap().pending_a
    }
    fn start(
        &mut self,
        _: &ParsedConfiguration,
        _: &DesktopTunnelOptions,
    ) -> Result<ServiceTunnelState, ServiceError> {
        panic!("factory/recovery must never start or adopt a member")
    }
    fn stop(&mut self) -> Result<ServiceTunnelState, ServiceError> {
        let mut events = self.events.lock().unwrap();
        events.calls.push(format!("stop {:?}", self.slot));
        if self.slot == TunnelSlot::A && events.fail_a_stop {
            return Err(ServiceError::Backend("fake_stop_failed".into()));
        }
        events.pending_a = false;
        Ok(ServiceTunnelState::Stopped)
    }
    fn status(&self) -> Result<ServiceTunnelState, ServiceError> {
        panic!("no native adoption/status during construction")
    }
}
struct Commands;
impl LinuxNetworkCommands for Commands {
    fn ip(&mut self, args: &[String]) -> io::Result<String> {
        panic!("no native commands during bootstrap or empty recovery: {args:?}")
    }
    fn busctl(&mut self, args: &[String]) -> io::Result<String> {
        panic!("no busctl: {args:?}")
    }
    fn interface_name(&self, _: u32) -> io::Result<String> {
        panic!("no native identity adoption")
    }
    fn interface_index(&self, _: &str) -> io::Result<u32> {
        panic!("no native identity adoption")
    }
}
type Pair = super::super::session::SessionNetwork<
    Backend,
    super::super::linux::LinuxNetwork<Commands>,
    FileNetworkJournal,
>;
fn pair(root: &Path, events: &Arc<Mutex<Events>>) -> Result<Pair, ServiceError> {
    open_linux_pair_with(
        root,
        scope(),
        "boot-one",
        uid(),
        |slot| {
            let mut state = events.lock().unwrap();
            state.calls.push(format!("construct {slot:?}"));
            if slot == TunnelSlot::B && state.fail_b_constructor {
                return Err(ServiceError::Backend("fake_constructor_failed".into()));
            }
            Ok(Backend {
                slot,
                events: events.clone(),
            })
        },
        || {
            let mut state = events.lock().unwrap();
            state.calls.push("commands".into());
            if state.fail_commands_constructor {
                return Err(io::Error::other("fake discovery failed"));
            }
            Ok(Commands)
        },
    )
}
fn assert_start_fenced(pair: &mut Pair) {
    let config = crate::parse_configuration("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n").unwrap();
    let probe = RedundantHealthProbe {
        kind: HealthProbeKind::DnsA,
        target_ipv4: "9.9.9.9".parse().unwrap(),
        query_name: "example.com".into(),
        timeout_ms: 4000,
    };
    let policy = super::super::session::NetworkPolicy {
        bypasses: vec![nelomai_client_tunnel::redundancy::network::RouteValue {
            destination: "192.0.2.1/32".parse().unwrap(),
            scope: nelomai_client_tunnel::redundancy::network::RouteScope::Global,
            interface: 5,
            gateway: Some("192.0.2.254".parse().unwrap()),
            metric: 42,
        }],
        retained_routes: vec![],
        dns_services: vec![],
        metric: 42,
    };
    assert!(pair
        .start_primary(&scope(), Slot::A, &config, probe, policy)
        .is_err());
    assert_eq!(pair.active(), None);
}

#[test]
fn fresh_factory_is_native_read_free_and_reopen_is_cleanup_only() {
    let dir = root();
    let events = Arc::new(Mutex::new(Events::default()));
    let fresh = pair(dir.path(), &events).unwrap();
    assert!(!fresh.cleanup_pending());
    assert_eq!(fresh.active(), None);
    drop(fresh);
    let mut recovered = pair(dir.path(), &events).unwrap();
    assert!(recovered.cleanup_pending());
    assert_start_fenced(&mut recovered);
    recovered.close(&scope()).unwrap();
    assert!(!recovered.cleanup_pending());
    assert_start_fenced(&mut recovered);
    assert_eq!(
        events.lock().unwrap().calls,
        [
            "construct A",
            "construct B",
            "commands",
            "construct A",
            "construct B",
            "commands"
        ]
    );
}

#[test]
fn backend_or_command_constructor_failure_leaves_only_cleanup_reopen() {
    for fail_commands in [false, true] {
        let dir = root();
        let events = Arc::new(Mutex::new(Events {
            fail_b_constructor: !fail_commands,
            fail_commands_constructor: fail_commands,
            ..Default::default()
        }));
        assert!(pair(dir.path(), &events).is_err());
        {
            let mut state = events.lock().unwrap();
            state.fail_b_constructor = false;
            state.fail_commands_constructor = false;
        }
        let mut recovered = pair(dir.path(), &events).unwrap();
        assert!(recovered.cleanup_pending());
        assert_start_fenced(&mut recovered);
        recovered.close(&scope()).unwrap();
        assert!(!recovered.cleanup_pending());
    }
}

#[test]
fn interrupted_bootstrap_with_only_boot_and_one_empty_slot_recovers_for_cleanup() {
    let dir = root();
    boot_only(dir.path());
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("slot-a"))
        .unwrap();
    let events = Arc::new(Mutex::new(Events::default()));
    let mut recovered = pair(dir.path(), &events).unwrap();
    assert_start_fenced(&mut recovered);
    assert!(recovered.cleanup_pending());
    recovered.close(&scope()).unwrap();
    assert!(!recovered.cleanup_pending());
    let mut reopened = pair(dir.path(), &events).unwrap();
    assert_start_fenced(&mut reopened);
}

#[test]
fn failed_native_cleanup_keeps_binding_until_successful_retry() {
    let dir = root();
    let events = Arc::new(Mutex::new(Events::default()));
    drop(pair(dir.path(), &events).unwrap());
    let mut allocator =
        BindingAllocator::open_for_owner(dir.path(), scope(), "boot-one", uid(), true).unwrap();
    allocator
        .reserve(
            TunnelSlot::A,
            10,
            "nlm-wga",
            &Occupancy::parse("[]", "[]", "[]", "[]").unwrap(),
        )
        .unwrap();
    drop(allocator);
    {
        let mut state = events.lock().unwrap();
        state.pending_a = true;
        state.fail_a_stop = true;
    }
    let mut recovered = pair(dir.path(), &events).unwrap();
    assert!(recovered.close(&scope()).is_err());
    assert!(recovered.cleanup_pending());
    assert_eq!(
        BindingAllocator::open_for_owner(dir.path(), scope(), "boot-one", uid(), false)
            .unwrap()
            .bindings()
            .len(),
        1
    );
    assert_start_fenced(&mut recovered);
    events.lock().unwrap().fail_a_stop = false;
    recovered.close(&scope()).unwrap();
    assert!(!recovered.cleanup_pending());
    assert!(
        BindingAllocator::open_for_owner(dir.path(), scope(), "boot-one", uid(), false)
            .unwrap()
            .bindings()
            .is_empty()
    );
}

#[test]
fn missing_network_journal_with_saved_binding_is_not_empty_bootstrap() {
    let dir = root();
    let events = Arc::new(Mutex::new(Events::default()));
    drop(pair(dir.path(), &events).unwrap());
    let mut allocator =
        BindingAllocator::open_for_owner(dir.path(), scope(), "boot-one", uid(), true).unwrap();
    allocator
        .reserve(
            TunnelSlot::A,
            10,
            "nlm-wga",
            &Occupancy::parse("[]", "[]", "[]", "[]").unwrap(),
        )
        .unwrap();
    fs::remove_file(dir.path().join("redundant-network.json")).unwrap();
    events.lock().unwrap().calls.clear();
    assert!(pair(dir.path(), &events).is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    assert!(!dir.path().join("redundant-network.json").exists());
}

#[test]
fn shared_snapshot_journal_coexists_with_cleanup_reopen_and_is_preserved() {
    let dir = root();
    let events = Arc::new(Mutex::new(Events::default()));
    drop(pair(dir.path(), &events).unwrap());
    let mut snapshot = ScopedJournal::<serde_json::Value>::open_named(
        dir.path(),
        scope(),
        uid(),
        "redundant-state.json",
    )
    .unwrap();
    let state = serde_json::json!({"snapshot": "owned by shared coordinator"});
    snapshot.save_state(&state).unwrap();
    let before = fs::read(dir.path().join("redundant-state.json")).unwrap();

    let mut recovered = pair(dir.path(), &events).unwrap();
    assert!(recovered.cleanup_pending());
    assert_start_fenced(&mut recovered);
    recovered.close(&scope()).unwrap();
    assert!(!recovered.cleanup_pending());
    assert_eq!(snapshot.load().unwrap(), Some(state));
    assert_eq!(
        fs::read(dir.path().join("redundant-state.json")).unwrap(),
        before
    );
}

#[test]
fn unknown_root_contents_are_never_adopted_after_boot_was_sealed() {
    let dir = root();
    boot_only(dir.path());
    fs::write(dir.path().join("foreign-state"), "untouched").unwrap();
    let events = Arc::new(Mutex::new(Events::default()));
    assert!(pair(dir.path(), &events).is_err());
    assert!(events.lock().unwrap().calls.is_empty());
    assert_eq!(
        fs::read_to_string(dir.path().join("foreign-state")).unwrap(),
        "untouched"
    );
}

#[test]
fn wrong_boot_scope_or_missing_network_with_member_state_blocks_before_construction() {
    for wrong in 0..3 {
        let dir = root();
        boot_only(dir.path());
        if wrong == 2 {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir.path().join("slot-a"))
                .unwrap();
            fs::write(dir.path().join("slot-a/member-state"), "unproven").unwrap();
        }
        let mut session_scope = scope();
        if wrong == 0 {
            session_scope.connection_generation += 1;
        }
        let boot = if wrong == 1 { "boot-two" } else { "boot-one" };
        let result = open_linux_pair_with::<Backend, Commands>(
            dir.path(),
            session_scope,
            boot,
            uid(),
            |_| panic!("untrusted factory reached backend"),
            || panic!("untrusted factory reached commands"),
        );
        assert!(result.is_err());
    }
}
