//! Destructive, opt-in test for a disposable Linux VM with real external peers.
//!
//! Run as root (no running nelomai service):
//! NELOMAI_ALLOW_DISPOSABLE_VM=1 NELOMAI_LINUX_NATIVE_FIXTURE=/root/native-pair.json \
//! cargo test -p nelomai-unix-service --test linux_native_pair -- --ignored --nocapture
//!
//! Fixture JSON: `scope: SessionScope`, `primary: protocol::Member` (A),
//! `standby: protocol::Member` (B), `role_generation: u64`,
//! `membership_generation: u64`, `role_response: RedundantRoleResponse`,
//! `dns_answer_ipv4: IPv4`, `traffic_address: IPv4:port`, `traffic_response: string`.
//! Configurations contain real kernel WG keys, distinct IPv4 UDP endpoints,
//! the SAME Address=/32 and DNS, AllowedIPs=0.0.0.0/0, no AWG parameters.
//! Both external peers serve UDP DNS at probe.target_ipv4:53 and TCP at
//! traffic_address. DNS answers probe.query_name with dns_answer_ipv4; TCP sends
//! traffic_response immediately. The role response is the panel fixture's
//! accepted B role: same session/leases, initial role_generation+1 and
//! membership_generation+1. The test does not contact a panel.
//! Requires iproute2, nftables, systemd-resolved with its working DNS stub.
//! Runtime journals are retained under the printed /tmp path even on failure.

#![cfg(target_os = "linux")]

use nelomai_client_tunnel::redundancy::{
    protocol::{Command, Member, Snapshot},
    session::SessionPhase,
    DnsProbe, NativeProbeSocket, ProbePoll, SessionScope, Slot,
};
use nelomai_contracts::RedundantRoleResponse;
use nelomai_unix_service::{
    member_network::{actor::CompositeBackend, runtime::NativePairFactory},
    parse_configuration, PlatformBackend, ServiceTunnelBackend,
};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    os::unix::fs::PermissionsExt,
    process::Command as Process,
    thread,
    time::{Duration, Instant},
};

type Backend = CompositeBackend<PlatformBackend, NativePairFactory>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    scope: SessionScope,
    primary: Member,
    standby: Member,
    role_generation: u64,
    membership_generation: u64,
    role_response: RedundantRoleResponse,
    dns_answer_ipv4: Ipv4Addr,
    traffic_address: SocketAddrV4,
    traffic_response: String,
}

fn run(program: &str, args: &[&str]) -> String {
    let output = Process::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

// Compare independently observed OS resources, including foreign routes/DNS.
fn network_state() -> Vec<String> {
    let mut state = Vec::new();
    let links: serde_json::Value = serde_json::from_str(&run("ip", &["-j", "link"])).unwrap();
    state.push(
        serde_json::to_string(
            &links
                .as_array()
                .unwrap()
                .iter()
                .map(|l| (&l["ifindex"], &l["ifname"]))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    for family in ["-4", "-6"] {
        for args in [
            vec!["-j", family, "route", "show", "table", "all"],
            vec!["-j", family, "rule", "show"],
        ] {
            let mut rows: Vec<serde_json::Value> = serde_json::from_str(&run("ip", &args)).unwrap();
            for row in &mut rows {
                row.as_object_mut().unwrap().remove("expires");
            }
            let mut rows = rows
                .iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<_>>();
            rows.sort();
            state.push(rows.join("\n"));
        }
    }
    for property in ["dns", "domain", "default-route"] {
        state.push(run("resolvectl", &[property]));
    }
    state
}

fn execute(backend: &mut Backend, command: Command) -> Snapshot {
    backend
        .redundant(command)
        .unwrap_or_else(|error| panic!("{error:?}; {}", backend.diagnostics().unwrap_or_default()))
}

fn wait_for(backend: &mut Backend, clock: Instant, ready: impl Fn(&Snapshot) -> bool) -> Snapshot {
    let deadline = Instant::now() + Duration::from_secs(50);
    loop {
        backend
            .tick(clock.elapsed().as_millis() as u64)
            .unwrap_or_else(|error| {
                panic!(
                    "tick: {error:?}; {}",
                    backend.diagnostics().unwrap_or_default()
                )
            });
        let snapshot = backend.current_redundancy_snapshot().unwrap();
        if ready(&snapshot) {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline,
            "native readiness deadline: {snapshot:?}; {}",
            backend.diagnostics().unwrap_or_default()
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn data_path(fixture: &Fixture, interface: &str) {
    let route: serde_json::Value = serde_json::from_str(&run(
        "ip",
        &[
            "-j",
            "route",
            "get",
            &fixture.traffic_address.ip().to_string(),
        ],
    ))
    .unwrap();
    assert_eq!(
        route[0]["dev"], interface,
        "ordinary data must follow the selected member"
    );
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::V4(fixture.traffic_address),
        Duration::from_secs(3),
    )
    .unwrap();
    let config = parse_configuration(fixture.primary.configuration.expose()).unwrap();
    assert_eq!(
        stream.local_addr().unwrap().ip(),
        config.addresses[0].addr()
    );
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut bytes = vec![0; fixture.traffic_response.len()];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, fixture.traffic_response.as_bytes());
    let dns = run(
        "resolvectl",
        &[
            "query",
            "--cache=no",
            "--type=A",
            &fixture.primary.probe.query_name,
        ],
    );
    assert!(
        dns.contains(&fixture.dns_answer_ipv4.to_string()),
        "system DNS: {dns}"
    );
}

#[test]
#[ignore = "requires root and NELOMAI_ALLOW_DISPOSABLE_VM=1 in a disposable VM with real WG/DNS/TCP fixtures"]
fn native_pair_promotes_with_real_evidence_and_leaves_no_network_state_after_restart() {
    assert_eq!(
        std::env::var("NELOMAI_ALLOW_DISPOSABLE_VM").as_deref(),
        Ok("1"),
        "explicit disposable VM authorization required"
    );
    assert_eq!(unsafe { libc::geteuid() }, 0, "requires root");
    let fixture: Fixture = serde_json::from_slice(
        &fs::read(std::env::var_os("NELOMAI_LINUX_NATIVE_FIXTURE").expect("set fixture JSON path"))
            .unwrap(),
    )
    .unwrap();
    assert!(
        !fixture.traffic_response.is_empty(),
        "fixture must require a nonempty TCP response"
    );
    assert_eq!(fixture.primary.slot, Slot::A);
    assert_eq!(fixture.standby.slot, Slot::B);
    let primary = parse_configuration(fixture.primary.configuration.expose()).unwrap();
    let standby = parse_configuration(fixture.standby.configuration.expose()).unwrap();
    assert_eq!(
        primary.transport,
        nelomai_client_tunnel::TunnelTransport::WireGuard
    );
    assert_eq!(standby.transport, primary.transport);
    assert_eq!(primary.addresses, standby.addresses);
    assert_eq!(primary.addresses.len(), 1);
    assert_eq!(primary.addresses[0].prefix_len(), 32);
    assert!(!primary.dns.is_empty());
    assert_eq!(primary.dns, standby.dns);
    let vip: Ipv4Addr = primary.addresses[0].addr().to_string().parse().unwrap();
    let endpoint = SocketAddrV4::new(
        primary.peers[0].endpoint.host().parse().unwrap(),
        primary.peers[0].endpoint.port(),
    );
    assert_ne!(primary.peers[0].endpoint, standby.peers[0].endpoint);
    let baseline = network_state();
    let root = tempfile::Builder::new()
        .prefix("nelomai-linux-native-")
        .tempdir()
        .unwrap()
        .keep();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("retained native lifecycle journals: {}", root.display());
    let single_root = root.join("single");
    let pair_root = root.join("pair");
    fs::create_dir(&single_root).unwrap();
    fs::create_dir(&pair_root).unwrap();
    fs::set_permissions(&pair_root, fs::Permissions::from_mode(0o700)).unwrap();
    // Kernel WG must not execute a substitute userspace/AWG binary.
    let single = PlatformBackend::new(root.join("absent-amneziawg-go"), &single_root).unwrap();
    let factory = NativePairFactory::new(&pair_root, fixture.scope.runtime, &root).unwrap();
    let mut backend = CompositeBackend::new(fixture.scope.runtime, single, factory).unwrap();
    let clock = Instant::now();
    let table = format!("nlm_native_{}", std::process::id());
    let mut fault_installed = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let start = |scope: SessionScope| Command::Start {
            scope,
            primary: serde_json::from_value(serde_json::to_value(&fixture.primary).unwrap())
                .unwrap(),
            role_generation: fixture.role_generation,
            membership_generation: fixture.membership_generation,
            warm_stop_v1: false,
            options: Default::default(),
        };
        let started = Instant::now();
        execute(&mut backend, start(fixture.scope.clone()));
        wait_for(&mut backend, clock, |s| s.primary_ready);
        eprintln!(
            "stage=Start primary_ready_ms={}",
            started.elapsed().as_millis()
        );
        data_path(&fixture, "nlm-wga");
        let before = backend.current_redundancy_snapshot().unwrap();
        let started = Instant::now();
        let attached = execute(
            &mut backend,
            Command::Attach {
                scope: fixture.scope.clone(),
                member: serde_json::from_value(serde_json::to_value(&fixture.standby).unwrap())
                    .unwrap(),
                expected_revision: before.session.local_revision,
                expected_network_epoch: before.session.network_epoch,
                expected_membership_generation: before.session.membership_generation,
                membership_generation: fixture.membership_generation + 1,
            },
        );
        assert_eq!(attached.session.active, Slot::A);
        wait_for(&mut backend, clock, |s| s.primary_ready && s.standby_ready);
        eprintln!(
            "stage=Attach standby_ready_ms={}",
            started.elapsed().as_millis()
        );
        // Actual device-bound DNS over each crypto path, same VIP. An unbound
        // fallback through A cannot pass B's decrypted receive-counter check.
        let mut indexes = Vec::new();
        for (name, member) in [("nlm-wga", &fixture.primary), ("nlm-wgb", &fixture.standby)] {
            let index: u32 = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            indexes.push(index);
            let counter = || {
                fs::read_to_string(format!("/sys/class/net/{name}/statistics/rx_packets"))
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .unwrap()
            };
            let received = counter();
            let socket = NativeProbeSocket::open(index, vip, member.probe.target_ipv4).unwrap();
            assert_eq!(socket.local_addr().unwrap().ip(), vip);
            let started = Instant::now();
            let mut probe = DnsProbe::start(
                socket,
                &member.probe.query_name,
                index as u16,
                0,
                u64::from(member.probe.timeout_ms),
            )
            .unwrap();
            loop {
                match probe.poll(started.elapsed().as_millis() as u64) {
                    ProbePoll::Pending => thread::sleep(Duration::from_millis(10)),
                    ProbePoll::Succeeded => break,
                    outcome => panic!("{name} real DNS failed: {outcome:?}"),
                }
            }
            assert!(counter() > received, "no decrypted DNS data on {name}");
        }
        assert_ne!(indexes[0], indexes[1]);
        data_path(&fixture, "nlm-wga");
        run("nft", &["create", "table", "inet", &table]);
        fault_installed = true;
        run(
            "nft",
            &[
                "add",
                "chain",
                "inet",
                &table,
                "output",
                "{ type filter hook output priority 0; policy accept; }",
            ],
        );
        let fault_started = Instant::now();
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                &table,
                "output",
                "ip",
                "daddr",
                &endpoint.ip().to_string(),
                "udp",
                "dport",
                &endpoint.port().to_string(),
                "counter",
                "drop",
            ],
        );
        let promoted = wait_for(&mut backend, clock, |s| s.session.active == Slot::B);
        eprintln!(
            "stage=Promotion fault_to_local_b_ms={}",
            fault_started.elapsed().as_millis()
        );
        assert!(!promoted.session.role_confirmed);
        assert_eq!(promoted.session.role_generation, fixture.role_generation);
        assert_eq!(
            promoted.session.membership_generation,
            fixture.membership_generation + 1
        );
        // Old ACKs cannot authorize the new local role/revision.
        assert!(backend
            .redundant(Command::ConfirmRole {
                scope: fixture.scope.clone(),
                expected_revision: attached.session.local_revision,
                expected_network_epoch: attached.session.network_epoch,
                response: fixture.role_response.clone(),
            })
            .is_err());
        assert!(
            !backend
                .current_redundancy_snapshot()
                .unwrap()
                .session
                .role_confirmed
        );
        let confirmed = execute(
            &mut backend,
            Command::ConfirmRole {
                scope: fixture.scope.clone(),
                expected_revision: promoted.session.local_revision,
                expected_network_epoch: promoted.session.network_epoch,
                response: fixture.role_response.clone(),
            },
        );
        assert!(confirmed.session.role_confirmed);
        assert_eq!(
            confirmed.session.role_generation,
            fixture.role_generation + 1
        );
        data_path(&fixture, "nlm-wgb");
        let started = Instant::now();
        let stopped = execute(
            &mut backend,
            Command::Stop {
                scope: fixture.scope.clone(),
            },
        );
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        eprintln!("stage=Stop clean_ack_ms={}", started.elapsed().as_millis());
        assert_eq!(
            network_state(),
            baseline,
            "Stop leaked interfaces/routes/rules/DNS"
        );
        run("nft", &["delete", "table", "inet", &table]);
        fault_installed = false;
        let mut next = fixture.scope.clone();
        next.connection_generation += 1;
        let started = Instant::now();
        execute(&mut backend, start(next.clone()));
        wait_for(&mut backend, clock, |s| s.primary_ready);
        eprintln!(
            "stage=RepeatStart primary_ready_ms={}",
            started.elapsed().as_millis()
        );
        assert!(
            backend
                .redundant(Command::Stop {
                    scope: fixture.scope.clone()
                })
                .is_err(),
            "old generation stopped the new session"
        );
        data_path(&fixture, "nlm-wga");
        let started = Instant::now();
        let stopped = execute(&mut backend, Command::Stop { scope: next });
        assert_eq!(stopped.session.phase, SessionPhase::Stopped);
        assert!(!stopped.cleanup_pending);
        eprintln!(
            "stage=RepeatStop clean_ack_ms={}",
            started.elapsed().as_millis()
        );
        assert_eq!(
            network_state(),
            baseline,
            "restart leaked interfaces/routes/rules/DNS"
        );
    }));
    // Preserve journals and still request exact production cleanup after RED.
    let cleanup = backend.shutdown();
    if fault_installed {
        run("nft", &["delete", "table", "inet", &table]);
    }
    if let Err(panic) = result {
        eprintln!("cleanup after failed native lifecycle: {cleanup:?}");
        std::panic::resume_unwind(panic);
    }
    cleanup.unwrap();
    assert_eq!(network_state(), baseline);
}
